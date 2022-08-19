// Copyright 2018 The mesh-chain Authors
package tribe

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"errors"
	"fmt"
	"github.com/MeshBoxTech/mesh-chain/consensus/tribe/vmcaller"
	"math/big"
	"math/rand"
	"sort"
	"time"

	"github.com/MeshBoxTech/mesh-chain/accounts"
	"github.com/MeshBoxTech/mesh-chain/common"
	"github.com/MeshBoxTech/mesh-chain/common/math"
	"github.com/MeshBoxTech/mesh-chain/consensus"
	"github.com/MeshBoxTech/mesh-chain/consensus/misc"
	"github.com/MeshBoxTech/mesh-chain/core/state"
	"github.com/MeshBoxTech/mesh-chain/core/types"
	"github.com/MeshBoxTech/mesh-chain/crypto"
	"github.com/MeshBoxTech/mesh-chain/crypto/sha3"
	"github.com/MeshBoxTech/mesh-chain/ethdb"
	"github.com/MeshBoxTech/mesh-chain/log"
	"github.com/MeshBoxTech/mesh-chain/params"
	"github.com/MeshBoxTech/mesh-chain/rlp"
	"github.com/MeshBoxTech/mesh-chain/rpc"
	lru "github.com/hashicorp/golang-lru"

	sha33 "golang.org/x/crypto/sha3"

	"github.com/holiman/uint256"
)

// sigHash returns the hash which is used as input for the proof-of-authority
// signing. It is the hash of the entire header apart from the 65 byte signature
// contained at the end of the extra data.
//
// Note, the method requires the extra data to be at least 65 bytes, otherwise it
// panics. This is done to avoid accidentally using both forms (signature present
// or not), which could be abused to produce different hashes for the same header.

// StateFn gets state by the state root hash.
type StateFn func(hash common.Hash) (*state.StateDB, error)

func sigHash(header *types.Header) (hash common.Hash) {
	hasher := sha3.NewKeccak256()

	err := rlp.Encode(hasher, []interface{}{
		header.ParentHash,
		header.UncleHash,
		header.Coinbase,
		header.Root,
		header.TxHash,
		header.ReceiptHash,
		header.Bloom,
		header.Difficulty,
		header.Number,
		header.GasLimit,
		header.GasUsed,
		header.Time,
		header.Extra[:len(header.Extra)-65], // Yes, this will panic if extra is too short
		header.MixDigest,
		header.Nonce,
	})
	if err != nil {
		panic(err)
	}
	hasher.Sum(hash[:0])
	return hash
}

func ecrecoverPubkey(header *types.Header, signature []byte) ([]byte, error) {
	pubkey, err := crypto.Ecrecover(sigHash(header).Bytes(), signature)
	return pubkey, err
}

// ecrecover extracts the Ethereum account address from a signed header.
func ecrecover(header *types.Header, t *Tribe) (common.Address, error) {
	sigcache := t.sigcache

	// If the signature's already cached, return that
	hash := header.Hash()
	if sigcache != nil {
		if address, known := sigcache.Get(hash); known {
			return address.(common.Address), nil
		}
	}
	// Retrieve the signature from the header extra-data
	if len(header.Extra) < extraSeal {
		return common.Address{}, errMissingSignature
	}
	// Recover the public key and the Ethereum address
	pubkey, err := ecrecoverPubkey(header, header.Extra[len(header.Extra)-extraSeal:])
	if err != nil {
		return common.Address{}, err
	}
	var signer common.Address
	copy(signer[:], crypto.Keccak256(pubkey[1:])[12:])
	if sigcache != nil {
		sigcache.Add(hash, signer)
	}

	return signer, nil
}

// signers set to the ones provided by the user.
func New(accman *accounts.Manager, config *params.TribeConfig, db ethdb.Database) *Tribe {
	sigcache, err := lru.NewARC(historyLimit)
	recents, _ := lru.NewARC(historyLimit)
	if err != nil {
		panic(err)
	}
	conf := *config
	if conf.Period <= 0 {
		conf.Period = blockPeriod
	}
	tribe := &Tribe{
		accman:   accman,
		config:   &conf,
		sigcache: sigcache,
		recents:  recents,
		db:       db,
	}
	return tribe
}

func (t *Tribe) Init(fn StateFn, nodekey *ecdsa.PrivateKey) {
	t.nodeKey = nodekey
	t.stateFn = fn
	t.abi = GetInteractiveABI()
	t.isInit = true
	log.Info("init tribe.status success.")
}
func (t *Tribe) GetConfig() *params.TribeConfig {
	return t.config
}
func (t *Tribe) SetConfig(config *params.TribeConfig) {
	t.config = config
}

// Author implements consensus.Engine, returning the Ethereum address recovered
// from the signature in the header's extra-data section.
func (t *Tribe) Author(header *types.Header) (common.Address, error) {
	var (
		coinbase common.Address
		err      error
	)
	if header.Coinbase == coinbase {
		coinbase, err = ecrecover(header, t)
	} else {
		coinbase = header.Coinbase
	}
	log.Debug("<<Tribe.Author>>", "num", header.Number, "coinbase", coinbase.Hex())
	return coinbase, err
}

// VerifyHeader checks whether a header conforms to the consensus rules.
func (t *Tribe) VerifyHeader(chain consensus.ChainReader, header *types.Header, seal bool) error {
	return t.verifyHeader(chain, header, nil)
}

// VerifyHeaders is similar to VerifyHeader, but verifies a batch of headers. The
// method returns a quit channel to abort the operations and a results channel to
// retrieve the async verifications (the order is that of the input slice).
func (t *Tribe) VerifyHeaders(chain consensus.ChainReader, headers []*types.Header, seals []bool) (chan<- struct{}, <-chan error) {
	abort := make(chan struct{})
	results := make(chan error)
	log.Debug("==> VerifyHeaders ", "currentNum", chain.CurrentHeader().Number.Int64(), "headers.len", len(headers))
	go func() {
		for i, header := range headers {
			err := t.verifyHeader(chain, header, headers[:i])
			select {
			case <-abort:
				return
			case results <- err:
			}
		}
	}()
	return abort, results
}

// verifyHeader checks whether a header conforms to the consensus rules.The
// caller may optionally pass in a batch of parents (ascending order) to avoid
// looking those up from the database. This is useful for concurrently verifying
// a batch of new headers.
func (t *Tribe) verifyHeader(chain consensus.ChainReader, header *types.Header, parents []*types.Header) (err error) {
	defer func() {
		if err != nil {
			log.Info(fmt.Sprintf("verifyHeader err return number=%s,err=%s", header.Number, err))
		}
	}()
	if header.Number == nil {
		return errUnknownBlock
	}
	number := header.Number.Uint64()
	// Don't waste time checking blocks from the future
	if header.Time.Cmp(big.NewInt(time.Now().Unix())) > 0 {
		return consensus.ErrFutureBlock
	}
	// Nonces must be 0x00..0 or 0xff..f, zeroes enforced on checkpoints
	if !bytes.Equal(header.Nonce[:], nonceSync) && !bytes.Equal(header.Nonce[:], nonceAsync) {
		return errInvalidNonce
	}

	// Check that the extra-data contains both the vanity and signature
	if len(header.Extra) < extraVanity {
		return errMissingVanity
	}
	if len(header.Extra) < extraVanity+extraSeal {
		return errMissingSignature
	}
	// check extra data
	isEpoch := number%t.config.Epoch == 0
	signersBytes := len(header.Extra) - extraVanity - extraSeal
	if !isEpoch && signersBytes != 0 {
		return errExtraValidators
	}

	if isEpoch && (signersBytes-extraVrf)%validatorBytesLength != 0 {
		return errInvalidSpanValidators
	}

	// Ensure that the mix digest is zero as we don't have fork protection currently
	if header.MixDigest != (common.Hash{}) {
		return errInvalidMixDigest
	}
	// Ensure that the block doesn't contain any uncles which are meaningless in PoA
	if header.UncleHash != uncleHash {
		return errInvalidUncleHash
	}
	// If all checks passed, validate any special fields for hard forks
	if err := misc.VerifyForkHashes(chain.Config(), header, false); err != nil {
		return err
	}
	// All basic checks passed, verify cascading fields
	err = t.verifyCascadingFields(chain, header, parents)
	if err != nil {
		log.Error("verifyCascadingFields", "num", header.Number.Int64(), "err", err)
	}
	return err
}

// verifyCascadingFields verifies all the header fields that are not standalone,
// rather depend on a batch of previous headers. The caller may optionally pass
// in a batch of parents (ascending order) to avoid looking those up from the
// database. This is useful for concurrently verifying a batch of new headers.
func (t *Tribe) verifyCascadingFields(chain consensus.ChainReader, header *types.Header, parents []*types.Header) (err error) {
	// The genesis block is the always valid dead-end
	number := header.Number.Uint64()
	if number == 0 {
		return nil
	}
	// Ensure that the block's timestamp isn't too close to it's parent
	var parent *types.Header
	if len(parents) > 0 {
		parent = parents[len(parents)-1]
	} else {
		parent = chain.GetHeader(header.ParentHash, number-1)
	}

	if parent == nil || parent.Number.Uint64() != number-1 || parent.Hash() != header.ParentHash {
		return consensus.ErrUnknownAncestor
	}
	//验证区块时间
	snap, err := t.snapshot(chain, number-1, header.ParentHash, parents)
	if err != nil {
		return err
	}
	err = t.blockTimeVerify(snap, header, parent)
	if err != nil {
		return err
	}

	// Verify that the gas limit is <= 2^63-1
	if header.GasLimit.Cmp(math.MaxBig63) > 0 {
		return fmt.Errorf("invalid gasLimit: have %v, max %v", header.GasLimit, math.MaxBig63)
	}
	// Verify that the gasUsed is <= gasLimit
	if header.GasUsed.Cmp(header.GasLimit) > 0 {
		return fmt.Errorf("invalid gasUsed: have %v, gasLimit %v", header.GasUsed, header.GasLimit)
	}

	// Verify that the gas limit remains within allowed bounds
	diff := new(big.Int).Set(parent.GasLimit)
	diff = diff.Sub(diff, header.GasLimit)
	diff.Abs(diff)

	limit := new(big.Int).Set(parent.GasLimit)
	limit = limit.Div(limit, params.GasLimitBoundDivisor)

	minGasLimit := params.MinGasLimit

	if diff.Cmp(limit) >= 0 || header.GasLimit.Cmp(minGasLimit) < 0 {
		return fmt.Errorf("invalid gas limit: have %v, want %v += %v", header.GasLimit, parent.GasLimit, limit)
	}

	// Verify that the block number is parent's +1
	if diff := new(big.Int).Sub(header.Number, parent.Number); diff.Cmp(big.NewInt(1)) != 0 {
		return consensus.ErrInvalidNumber
	}

	return t.verifySeal(chain, header, parents)
}

// VerifyUncles implements consensus.Engine, always returning an error for any
// uncles as this consensus mechanism doesn't permit uncles.
func (t *Tribe) VerifyUncles(chain consensus.ChainReader, block *types.Block) error {
	if len(block.Uncles()) > 0 {
		return errors.New("uncles not allowed")
	}
	return nil
}

// VerifySeal implements consensus.Engine, checking whether the signature contained
// in the header satisfies the consensus protocol requirements.
// don't support remote miner agent, these code never reached
func (t *Tribe) VerifySeal(chain consensus.ChainReader, header *types.Header) error {
	e := t.verifySeal(chain, header, nil)
	if e != nil {
		log.Error("Tribe.VerifySeal", "err", e)
	}
	return e
}

func (t *Tribe) verifySeal(chain consensus.ChainReader, header *types.Header, parents []*types.Header) error {
	// Verifying the genesis block is not supported
	number := header.Number.Uint64()
	if number == 0 {
		return errUnknownBlock
	}
	// Retrieve the snapshot needed to verify this header and cache it
	snap, err := t.snapshot(chain, number-1, header.ParentHash, parents)
	if err != nil {
		return err
	}
	//
	//// Resolve the authorization key and check against signers
	signer, err := ecrecover(header, t)
	if err != nil {
		return err
	}
	if signer != header.Coinbase {
		return errInvalidCoinbase
	}

	if number%t.config.Epoch == 0 {
		//verify vrf
		msg := header.Number.Bytes()
		sig := header.Extra[len(header.Extra)-extraSeal:]
		pubbuf, err := ecrecoverPubkey(header, sig)
		if err != nil {
			return err
		}
		x, y := elliptic.Unmarshal(crypto.S256(), pubbuf)
		pubkey := ecdsa.PublicKey{Curve: crypto.S256(), X: x, Y: y}
		err = crypto.SimpleVRFVerify(&pubkey, msg, header.Extra[extraVanity:extraVanity+extraVrf])
		if err != nil {
			return err
		}
	}

	if _, ok := snap.Validators[signer]; !ok {
		return errUnauthorizedValidator
	}
	inturn := snap.inturn(signer)
	if inturn && header.Difficulty.Cmp(diffInTurn) != 0 {
		return errInvalidDifficulty
	}
	if !inturn && header.Difficulty.Cmp(diffNoTurn) != 0 {
		return errInvalidDifficulty
	}

	log.Debug("verifySeal", "number", number, "signer", signer.Hex())
	return nil
}

// Prepare implements consensus.Engine, preparing all the consensus fields of the
// header for running the transactions on top.
func (t *Tribe) Prepare(chain consensus.ChainReader, header *types.Header) error {
	number := header.Number.Uint64()

	snap, err := t.snapshot(chain, number-1, header.ParentHash, nil)
	if err != nil {
		return err
	}
	header.Coinbase = t.GetMinerAddress()
	header.Nonce = types.BlockNonce{}
	copy(header.Nonce[:], nonceAsync)
	//log.Debug("fix extra", "extra-len", len(header.Extra), "extraVanity", extraVanity)
	if len(header.Extra) < extraVanity {
		header.Extra = append(header.Extra, bytes.Repeat([]byte{0x00}, extraVanity-len(header.Extra))...)
	}
	header.Extra = header.Extra[:extraVanity]
	if number%t.config.Epoch == 0 {
		vrf, err := crypto.SimpleVRF2Bytes(t.nodeKey, header.Number.Bytes())
		if err != nil {
			return err
		}
		header.Extra = append(header.Extra, vrf...)
		newValidators, err := t.getNewValidators(chain, header)
		if err != nil {
			return err
		}
		for _, validator := range newValidators {
			header.Extra = append(header.Extra, validator.Bytes()...)
		}
	}
	header.Extra = append(header.Extra, make([]byte, extraSeal)...)

	// Extra : append sig to last 65 bytes <<<<

	// Mix digest is reserved for now, set to empty
	header.MixDigest = common.Hash{}

	// Ensure the timestamp has the correct delay
	parent := chain.GetHeader(header.ParentHash, number-1)
	if parent == nil {
		return consensus.ErrUnknownAncestor
	}
	// Set the correct difficulty
	header.Difficulty = t.CalcDifficulty(chain, header.Time.Uint64(), parent)
	header.Time = new(big.Int).Add(parent.Time, new(big.Int).SetUint64(t.config.Period))

	//替补出块延迟
	delay := backOffTime(snap, t.GetMinerAddress())
	header.Time = new(big.Int).Add(header.Time, new(big.Int).SetUint64(delay))

	if header.Time.Int64() < time.Now().Unix() {
		header.Time = big.NewInt(time.Now().Unix())
	}
	return nil
}

// Finalize implements consensus.Engine, ensuring no uncles are set, nor block
// rewards given, and returns the final block.
func (t *Tribe) Finalize(chain consensus.ChainReader, header *types.Header, state *state.StateDB, txs []*types.Transaction, uncles []*types.Header, receipts []*types.Receipt) (*types.Block, error) {
	// Accumulate any block and uncle rewards and commit the final state root
	if header.Number.Cmp(common.Big1) == 0 {
		if err := t.initializeSystemContracts(chain, header, state); err != nil {
			log.Error("Initialize system contracts failed", "err", err)
			return nil, err
		}
	}

	if header.Difficulty.Cmp(diffInTurn) != 0 {
		if err := t.tryPunishValidator(chain, header, state); err != nil {
			return nil, err
		}
	}

	if header.Number.Uint64()%t.config.Epoch == 0 {
		newValidators, err := t.doSomethingAtEpoch(chain, header, state)
		if err != nil {
			return nil, err
		}
		//verify validators
		validatorsBytes := make([]byte, len(newValidators)*common.AddressLength)
		for i, validator := range newValidators {
			copy(validatorsBytes[i*common.AddressLength:], validator.Bytes())
		}
		extraSuffix := len(header.Extra) - extraSeal
		if !bytes.Equal(header.Extra[extraVanity+extraVrf:extraSuffix], validatorsBytes) {
			return nil, errInvalidExtraValidators
		}
	}
	t.accumulateRewards(chain, state, header)

	header.Root = state.IntermediateRoot(chain.Config().IsEIP158(header.Number))
	//there is no uncle in triple
	header.UncleHash = types.CalcUncleHash(nil)
	return types.NewBlock(header, txs, nil, receipts), nil
}

// Seal implements consensus.Engine, attempting to create a sealed block using
// the local signing credentials.
func (t *Tribe) Seal(chain consensus.ChainReader, block *types.Block, stop <-chan struct{}) (*types.Block, error) {
	header := block.Header()
	// Sealing the genesis block is not supported
	number := header.Number.Uint64()
	if number == 0 {
		return nil, errUnknownBlock
	}

	snap, err := t.snapshot(chain, number-1, header.ParentHash, nil)
	if err != nil {
		return nil, err
	}
	// Bail out if we're unauthorized to sign a block
	if _, authorized := snap.Validators[t.GetMinerAddress()]; !authorized {
		return nil, errUnauthorizedValidator
	}

	now := time.Now()
	delay := time.Unix(header.Time.Int64(), 0).Sub(now)
	log.Info(fmt.Sprintf("Seal -> num=%d, diff=%d, miner=%s, delay=%d", number, header.Difficulty, header.Coinbase.Hex(), delay))
	select {
	case <-stop:
		log.Warn(fmt.Sprintf("🐦 cancel -> num=%d, diff=%d, miner=%s, delay=%d", number, header.Difficulty, header.Coinbase.Hex(), delay))
		return nil, nil
	case <-time.After(delay):
	}

	// Sign all the things!
	hash := sigHash(header).Bytes()
	sighash, err := crypto.Sign(hash, t.nodeKey)
	if err != nil {
		return nil, err
	}
	copy(header.Extra[len(header.Extra)-extraSeal:], sighash)
	blk := block.WithSeal(header)
	return blk, nil
}

// CalcDifficulty is the difficulty adjustment algorithm. It returns the difficulty
// that a new block should have based on the previous blocks in the chain and the
// current signer.
func (t *Tribe) CalcDifficulty(chain consensus.ChainReader, time uint64, parent *types.Header) *big.Int {
	log.Debug("CalcDifficulty", "ParentNumber", parent.Number.Int64(), "CurrentNumber:", chain.CurrentHeader().Number.Int64())
	snap, err := t.snapshot(chain, parent.Number.Uint64(), parent.Hash(), nil)
	if err != nil {
		return nil
	}
	return calcDifficulty(snap, t.GetMinerAddress())
}
func calcDifficulty(snap *Snapshot, validator common.Address) *big.Int {
	if snap.inturn(validator) {
		return new(big.Int).Set(diffInTurn)
	}
	return new(big.Int).Set(diffNoTurn)
}
func (self *Tribe) GetMinerAddress() common.Address {
	if self.nodeKey == nil {
		panic(errors.New("GetMinerAddress but nodekey not ready"))
	}
	pub := self.nodeKey.PublicKey
	add := crypto.PubkeyToAddress(pub)
	return add
}
func (self *Tribe) GetMinerAddressByChan(rtn chan common.Address) {
	go func() {
		for {
			if self.nodeKey != nil && self.isInit {
				break
			}
			<-time.After(time.Second)
		}
		pub := self.nodeKey.PublicKey
		rtn <- crypto.PubkeyToAddress(pub)
	}()
}
func (t *Tribe) getNodekey() *ecdsa.PrivateKey {
	if t.nodeKey == nil {
		panic(errors.New("GetNodekey but nodekey not ready"))
	}
	return t.nodeKey
}

// initializeSystemContracts initializes all genesis system contracts.
func (t *Tribe) initializeSystemContracts(chain consensus.ChainReader, header *types.Header, state *state.StateDB) error {
	snap, err := t.snapshot(chain, 0, header.ParentHash, nil)
	if err != nil {
		return err
	}

	genesisValidators := snap.validators()
	if len(genesisValidators) == 0 || len(genesisValidators) > maxValidators {
		return errInvalidValidatorsLength
	}

	method := "initialize"
	contracts := []struct {
		addr    common.Address
		packFun func() ([]byte, error)
	}{
		{params.ValidatorsContractAddr, func() ([]byte, error) {
			return t.abi[ValidatorsContractName].Pack(method, genesisValidators, params.OwnerAddress)
		}},
	}

	for _, contract := range contracts {
		data, err := contract.packFun()
		if err != nil {
			return err
		}
		chainConfig := params.MainnetChainConfig
		if params.IsTestnet() {
			chainConfig = params.TestChainConfig
		}
		nonce := state.GetNonce(header.Coinbase)
		msg := vmcaller.NewLegacyMessage(header.Coinbase, &contract.addr, nonce, new(big.Int), new(big.Int).SetUint64(math.MaxUint64), new(big.Int), data, true)
		if _, err := vmcaller.ExecuteMsg(msg, state, header, newChainContext(chain, t), chainConfig); err != nil {
			return err
		}
	}

	return nil
}

func (t *Tribe) getNewValidators(chain consensus.ChainReader, header *types.Header) ([]common.Address, error) {
	if header.Number.Uint64() == 0 {
		validators := make([]common.Address, (len(header.Extra)-extraVanity-extraVrf-extraSeal)/common.AddressLength)
		for i := 0; i < len(validators); i++ {
			copy(validators[i][:], header.Extra[extraVanity+extraVrf+i*common.AddressLength:])
		}
		return validators, nil
	}
	parent := chain.GetHeader(header.ParentHash, header.Number.Uint64()-1)
	if parent == nil {
		return []common.Address{}, consensus.ErrUnknownAncestor
	}
	number := header.Number.Uint64()
	if number%t.config.Epoch != 0 {
		return []common.Address{}, consensus.ErrInvalidNumber
	}

	statedb, err := t.stateFn(parent.Root)
	if err != nil {
		return []common.Address{}, err
	}

	// method
	method := "getNewValidators"
	vrf := header.Extra[extraVanity : extraVanity+extraVrf]
	rand := new(big.Int).SetBytes(vrf)
	v, _ := uint256.FromBig(rand)
	data, err := t.abi[ValidatorsContractName].Pack(method, v.ToBig())
	if err != nil {
		return nil, err
	}

	// call contract
	nonce := statedb.GetNonce(header.Coinbase)
	msg := vmcaller.NewLegacyMessage(header.Coinbase, &params.ValidatorsContractAddr, nonce, new(big.Int), new(big.Int).SetUint64(math.MaxUint64), new(big.Int), data, false)
	//
	chainConfig := params.MainnetChainConfig
	if params.IsTestnet() {
		chainConfig = params.TestChainConfig
	}
	result, err := vmcaller.ExecuteMsg(msg, statedb, parent, newChainContext(chain, t), chainConfig)
	if err != nil {
		log.Error("Can't decrease missed blocks counter for validator", "err", err)
		return nil, err
	}
	var out []common.Address
	if err := t.abi[ValidatorsContractName].Unpack(&out, method, result); err != nil {
		return []common.Address{}, err
	}
	sort.Sort(validatorsAscending(out))
	return out, nil
}
func (t *Tribe) punishValidator(val common.Address, chain consensus.ChainReader, header *types.Header, state *state.StateDB) error {
	// method
	method := "punishValidator"
	data, err := t.abi[ValidatorsContractName].Pack(method, val)
	if err != nil {
		log.Error("Can't pack data for punish", "error", err)
		return err
	}
	log.Debug("tryPunishValidator", "addr=", val, "number=", header.Number.Uint64())
	// call contract
	nonce := state.GetNonce(header.Coinbase)
	chainConfig := params.MainnetChainConfig
	if params.IsTestnet() {
		chainConfig = params.TestChainConfig
	}
	msg := vmcaller.NewLegacyMessage(header.Coinbase, &params.ValidatorsContractAddr, nonce, new(big.Int), new(big.Int).SetUint64(math.MaxUint64), new(big.Int), data, true)
	if _, err := vmcaller.ExecuteMsg(msg, state, header, newChainContext(chain, t), chainConfig); err != nil {
		log.Error("Can't punish validator", "err", err)
		return err
	}
	//log.Warn("punish validator success","addr=",val.String())
	return nil
}

func (t *Tribe) tryPunishValidator(chain consensus.ChainReader, header *types.Header, state *state.StateDB) error {
	number := header.Number.Uint64()
	snap, err := t.snapshot(chain, number-1, header.ParentHash, nil)
	if err != nil {
		return err
	}
	validators := snap.validators()
	outTurnValidator := validators[number%uint64(len(validators))]
	if err := t.punishValidator(outTurnValidator, chain, header, state); err != nil {
		return err
	}
	return nil
}

func (t *Tribe) doSomethingAtEpoch(chain consensus.ChainReader, header *types.Header, state *state.StateDB) ([]common.Address, error) {
	newValidators, err := t.getNewValidators(chain, header)
	if err != nil {
		return []common.Address{}, err
	}
	return newValidators, nil
}

// snapshot retrieves the authorization snapshot at a given point in time.
func (t *Tribe) snapshot(chain consensus.ChainReader, number uint64, hash common.Hash, parents []*types.Header) (*Snapshot, error) {
	// Search for a snapshot in memory or on disk for checkpoints
	var (
		headers []*types.Header
		snap    *Snapshot
	)
	for snap == nil {
		// If an in-memory snapshot was found, use that
		if s, ok := t.recents.Get(hash); ok {
			snap = s.(*Snapshot)
			break
		}
		// If an on-disk checkpoint snapshot can be found, use that
		if number%checkpointInterval == 0 {
			if s, err := loadSnapshot(t.config, t.db, hash); err == nil {
				log.Trace("Loaded snapshot from disk", "number", number, "hash", hash)
				snap = s
				break
			}
		}
		// If we're at the genesis, snapshot the initial state. Alternatively if we're
		// at a checkpoint block without a parent (light client CHT), or we have piled
		// up more headers than allowed to be reorged (chain reinit from a freezer),
		// consider the checkpoint trusted and snapshot it.
		if number == 0 {
			checkpoint := chain.GetHeaderByNumber(number)
			if checkpoint != nil {
				hash := checkpoint.Hash()

				// Check that the extra-data contains both the vanity and signature
				if len(checkpoint.Extra) < extraVanity {
					return nil, errMissingVanity
				}
				if len(checkpoint.Extra) < extraVanity+extraSeal {
					return nil, errMissingSignature
				}
				// check extra data
				signersBytes := len(checkpoint.Extra) - extraVanity - extraSeal
				if (signersBytes-extraVrf)%validatorBytesLength != 0 {
					return nil, errInvalidSpanValidators
				}

				validators := make([]common.Address, (len(checkpoint.Extra)-extraVanity-extraVrf-extraSeal)/common.AddressLength)

				for i := 0; i < len(validators); i++ {
					copy(validators[i][:], checkpoint.Extra[extraVanity+extraVrf+i*common.AddressLength:])
				}
				snap = newSnapshot(t.config, number, hash, validators)
				if err := snap.store(t.db); err != nil {
					return nil, err
				}
				log.Debug("Stored checkpoint snapshot to disk", "number", number, "hash", hash)
				break
			}
		}
		// No snapshot for this header, gather the header and move backward
		var header *types.Header
		if len(parents) > 0 {
			// If we have explicit parents, pick from there (enforced)
			header = parents[len(parents)-1]
			if header.Hash() != hash || header.Number.Uint64() != number {
				return nil, consensus.ErrUnknownAncestor
			}
			parents = parents[:len(parents)-1]
		} else {
			// No explicit parents (or no more left), reach out to the database
			header = chain.GetHeader(hash, number)
			if header == nil {
				return nil, consensus.ErrUnknownAncestor
			}
		}
		headers = append(headers, header)
		number, hash = number-1, header.ParentHash
	}
	// Previous snapshot found, apply any pending headers on top of it
	for i := 0; i < len(headers)/2; i++ {
		headers[i], headers[len(headers)-1-i] = headers[len(headers)-1-i], headers[i]
	}
	snap, err := snap.apply(headers, chain, parents, t)
	if err != nil {
		return nil, err
	}
	t.recents.Add(snap.Hash, snap)

	// If we've generated a new checkpoint snapshot, save to disk
	if snap.Number%checkpointInterval == 0 && len(headers) > 0 {
		if err = snap.store(t.db); err != nil {
			return nil, err
		}
		log.Trace("Stored snapshot to disk", "number", snap.Number, "hash", snap.Hash)
	}
	return snap, err
}
func (t *Tribe) blockTimeVerify(snap *Snapshot, header, parent *types.Header) error {
	if header.Time.Uint64() < parent.Time.Uint64()+t.config.Period+backOffTime(snap, header.Coinbase) {
		return consensus.ErrFutureBlock
	}
	return nil
}

// APIs implements consensus.Engine, returning the user facing RPC API to allow
// controlling the signer voting.
func (t *Tribe) APIs(chain consensus.ChainReader) []rpc.API {
	return []rpc.API{{
		Namespace: "tribe",
		Version:   "0.0.1",
		Service:   &API{accman: t.accman, chain: chain, tribe: t},
		Public:    false,
	}}
}

// AccumulateRewards credits the coinbase of the given block with the validator
func accumulateTotalBalance(state *state.StateDB, blockReward *big.Int) {
	val := state.GetState(params.MeshContractAddress, params.TotalMeshHash)
	newValue := val.Big().Add(val.Big(), blockReward)
	vals := common.BytesToHash(newValue.Bytes())
	state.SetState(params.MeshContractAddress, params.TotalMeshHash, vals)
}

func GetMESHBalanceKey(addr common.Address) common.Hash {
	position := common.Big1
	hasher := sha33.NewLegacyKeccak256()
	hasher.Write(common.LeftPadBytes(addr.Bytes(), 32))
	hasher.Write(common.LeftPadBytes(position.Bytes(), 32))
	digest := hasher.Sum(nil)
	return common.BytesToHash(digest)
}

type bindInfo struct {
	From common.Address
	Nids []common.Address
}

func (t *Tribe) getBindInfo(chain consensus.ChainReader, header *types.Header, addr common.Address) (bindInfo, error) {
	if header.Number.Uint64() == 0 {
		return bindInfo{From: addr, Nids: make([]common.Address, 0)}, nil
	}
	parent := chain.GetHeader(header.ParentHash, header.Number.Uint64()-1)
	if parent == nil {
		return bindInfo{}, consensus.ErrUnknownAncestor
	}
	statedb, err := t.stateFn(parent.Root)
	if err != nil {
		return bindInfo{}, err
	}
	// method
	method := "bindInfo"
	data, err := t.abi[ValidatorsContractName].Pack(method, addr)
	if err != nil {
		return bindInfo{}, err
	}

	// call contract
	nonce := statedb.GetNonce(header.Coinbase)
	msg := vmcaller.NewLegacyMessage(header.Coinbase, &params.ValidatorsContractAddr, nonce, new(big.Int), new(big.Int).SetUint64(math.MaxUint64), new(big.Int), data, false)

	chainConfig := params.MainnetChainConfig
	if params.IsTestnet() {
		chainConfig = params.TestChainConfig
	}
	result, err := vmcaller.ExecuteMsg(msg, statedb, parent, newChainContext(chain, t), chainConfig)
	if err != nil {
		log.Error("Can't decrease missed blocks counter for validator", "err", err)
		return bindInfo{}, err
	}

	var out = bindInfo{}
	if err := t.abi[ValidatorsContractName].Unpack(&out, method, result); err != nil {
		return bindInfo{}, err
	}
	return out, nil
}
func (t *Tribe) accumulateAccountsBalance(chain consensus.ChainReader, header *types.Header, state *state.StateDB, blockReward *big.Int, addr common.Address) {
	//get miner bind wallet for receive rewards
	bindInfo, err := t.getBindInfo(chain, header, addr)
	if err == nil {
		addr = bindInfo.From
	}
	key := GetMESHBalanceKey(addr)
	val := state.GetState(params.MeshContractAddress, key)
	newVal := val.Big().Add(val.Big(), blockReward)
	state.SetState(params.MeshContractAddress, key, common.BytesToHash(newVal.Bytes()))
}

func (t *Tribe) accumulatePOMRewards(chain consensus.ChainReader, state *state.StateDB, header *types.Header) {
	// Select the correct block reward based on chain progression
	blockReward := new(big.Int).Set(MeshRewardForPom)

	number := new(big.Int).Set(header.Number)
	number = number.Div(number, big.NewInt(int64(BlockRewardReducedInterval)))
	blockReward = blockReward.Rsh(blockReward, uint(number.Int64()))

	accumulateTotalBalance(state, blockReward)

	// Miner will send tx to deposit block rewards to pom contract, add to his balance first.
	key := GetMESHBalanceKey(params.PomContractAddr)
	val := state.GetState(params.MeshContractAddress, key)
	newVal := val.Big().Add(val.Big(), blockReward)
	state.SetState(params.MeshContractAddress, key, common.BytesToHash(newVal.Bytes()))

	//then call sendPomEpochReward to distribute mesh all pom nodes
	method := "sendPomEpochReward"
	data, err := t.abi[PomContractName].Pack(method, blockReward)
	if err != nil {
		log.Error("Can't pack data for distributeBlockReward", "err", err)
		return
	}

	nonce := state.GetNonce(header.Coinbase)
	msg := vmcaller.NewLegacyMessage(header.Coinbase, &params.PomContractAddr, nonce, new(big.Int), new(big.Int).SetUint64(math.MaxUint64), new(big.Int), data, true)
	chainConfig := params.MainnetChainConfig
	if params.IsTestnet() {
		chainConfig = params.TestChainConfig
	}
	if _, err := vmcaller.ExecuteMsg(msg, state, header, newChainContext(chain, t), chainConfig); err != nil {
		log.Error("can't ExecuteMsg", "err", err)
		return
	}

	return

}
func (t *Tribe) accumulateRewards(chain consensus.ChainReader, state *state.StateDB, header *types.Header) {
	// Select the correct block reward based on chain progression
	blockReward := new(big.Int).Set(MeshRewardForValidator)
	number := new(big.Int).Set(header.Number)
	number = number.Div(number, big.NewInt(int64(BlockRewardReducedInterval)))
	blockReward = blockReward.Rsh(blockReward, uint(number.Int64()))

	accumulateTotalBalance(state, blockReward)
	t.accumulateAccountsBalance(chain, header, state, blockReward, header.Coinbase)

	//每个epoch最后一个区块发放pom奖励
	if header.Number.Uint64()%t.config.Epoch == 0 {
		t.accumulatePOMRewards(chain, state, header)
	}
}

func backOffTime(snap *Snapshot, val common.Address) uint64 {
	if snap.inturn(val) {
		return 0
	} else {
		idx := snap.indexOfVal(val)
		if idx < 0 {
			// The backOffTime does not matter when a validator is not authorized.
			return 0
		}
		s := rand.NewSource(int64(snap.Number))
		r := rand.New(s)
		n := len(snap.Validators)
		backOffSteps := make([]uint64, 0, n)
		for idx := uint64(0); idx < uint64(n); idx++ {
			backOffSteps = append(backOffSteps, idx)
		}
		r.Shuffle(n, func(i, j int) {
			backOffSteps[i], backOffSteps[j] = backOffSteps[j], backOffSteps[i]
		})
		delay := initialBackOffTime + backOffSteps[idx]*wiggleTime
		return delay
	}
}

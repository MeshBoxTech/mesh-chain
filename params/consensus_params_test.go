package params

import (
	"github.com/MeshBoxTech/mesh-chain/common"
	"math/big"
	"sync"
	"testing"
)

type ChiefStatus1 struct {
	NumberList []*big.Int
	BlackList  []*big.Int
}

type ChiefStatus2 struct {
	NumberList []*big.Int
	BlackList  []*big.Int
}

func TestFooBar(t *testing.T) {
	a := ChiefStatus1{[]*big.Int{big.NewInt(1)}, []*big.Int{big.NewInt(2)}}
	t.Log(a)
	b := ChiefStatus2(a)
	t.Log(b)
	var x []common.Address
	x = nil
	t.Log(x == nil)
}

func TestAddr(t *testing.T) {
	add1 := common.HexToAddress("0xAd4c80164065a3c33dD2014908c7563eFf88aB49")
	add2 := common.HexToAddress("0xAd4c80164065a3c33dD2014908c7563eFf88Ab49")
	t.Log(add1 == add2)
}

func TestError(t *testing.T) {
	ch := make(chan int)
	sm := new(sync.Map)
	sm.Store("foo", "bar")
	sm.Store("hello", "world")

	sm.Range(func(k, v interface{}) bool {
		defer func() {
			if err := recover(); err != nil {
				t.Log(k, v, "err:", err)
			}
		}()
		defer close(ch)
		t.Log(k, v)
		return true
	})

}

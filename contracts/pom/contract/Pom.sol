// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.0;
import "@openzeppelin/contracts/access/Ownable.sol";
import "@openzeppelin/contracts/token/ERC20/IERC20.sol";
contract POM is Ownable{
  address constant meshToken = 0x0000000000000000000000000000000000002000;
  //挑战周期120个区块间隔
  uint constant public challengeInterval = 120;
  //本次挑战从选择目标节点到提交POMReceipt有效时间为20个区块
  uint constant public challengeDelay= 20;
  //网络中meshbox设备信息
  struct MeshBoxInfo{
    string id;
    address addr;
  }
  //pom挑战信息
  struct POMChallenge{
    address challenger;
    address target;
    address [] witness;
  }
  //挑战者、目标节点、见证人挑战得分
  struct RewardFactorForChallenger{
     address challenger;
     uint score;
  }
  struct RewardFactorForTarget{
     address target;
     uint score;
  }
  struct RewardFactorForWitness{
     address[] witness;
     uint score;
  }
  //记录挑战者上一次挑战的区块号和目标节点
  struct ChallengeInfo{
     address target;
     uint lastChallengeBlock;
  }
  event AddMeshBox(string id,address addr);
  event RemoveMeshBox(address addr);
  event GetTarget(address addr);

  //网络中的meshbox设备列表
  mapping (address => MeshBoxInfo)meshboxMap;
  address [] meshboxList;
  mapping (address => uint256) meshboxListIndex;

  //当前epoch中的pom列表
  POMChallenge []challengeList;
  //挑战者上一次挑战的记录
  mapping(address => ChallengeInfo) lastChallenge;
  modifier onlyMiner() virtual {
		require(msg.sender == block.coinbase, "Miner only");
		_;
	}
  //manager添加许可的meshbox设备到网络中
  function addMeshBox(string memory id,address addr) public onlyOwner{
    require (addr != address(0), "invalid address");
    require (meshboxMap[addr].addr == address(0), "duplicate address");

    meshboxMap[addr] = MeshBoxInfo(id,addr);
    meshboxList.push(addr);
    meshboxListIndex[addr] = meshboxList.length - 1;

    emit AddMeshBox(id, addr);
  }
  //manager移除网络中meshbox设备
  function removeMeshBox(address addr) public onlyOwner{
    require (addr != address(0), "Invalid address");
    require (meshboxMap[addr].addr != address(0), "address not exist");

    delete meshboxMap[addr];
    uint256 index = meshboxListIndex[addr];
    meshboxList[index] = meshboxList[meshboxList.length-1];
    meshboxList.pop();

    emit RemoveMeshBox(addr);
  }
  //challenger获取本次挑战的target
  function getTarget() public returns (address){
    require(block.number-lastChallenge[msg.sender].lastChallengeBlock >= challengeInterval,"interval is too short");
    require(meshboxList.length>=3,"too few meshbox");
    uint random = uint(keccak256(abi.encodePacked(msg.sender,block.number)));
    uint randIndex =  random % meshboxList.length;
    address target = meshboxList[randIndex];
    //目标节点不能选自己,重新选择randIndex+1节点（注意：如果randIndex是数组最后一个节点，则选择数组第0个元素）
    if (target == msg.sender){
       if (randIndex == meshboxList.length-1){
           target = meshboxList[0];
       }else{
           target = meshboxList[randIndex+1];
       }
    }
    lastChallenge[msg.sender] = ChallengeInfo(target,block.number);
    emit GetTarget(target);
    return target;
 }
   //challenger获取本次挑战的target
  function getLastChallengeBlock(address challenger) public view returns (uint){
    return lastChallenge[challenger].lastChallengeBlock;
 }
  //挑战者发送挑战证明数据
  function sendPOMReceipt(address target, uint8[] memory v, bytes32[] memory r, bytes32[] memory s) public{
    require (meshboxMap[msg.sender].addr != address(0), "address not exist");
    require (lastChallenge[msg.sender].target == target, "target not right");
    require (block.number-lastChallenge[msg.sender].lastChallengeBlock <= challengeDelay,"delay is too long");
    require (v.length == r.length, "wrong length");
    require (r.length == s.length, "wrong length");

    address [] memory witness = new address[](v.length);
    for (uint i=0;i<v.length;i++){
       bytes32 hash = keccak256(abi.encodePacked(target));
       address signer = ecrecover(hash, v[i], r[i], s[i]);
       require (meshboxMap[signer].addr != address(0), "address not exist");
       witness[i] = signer;
    }
    POMChallenge memory challenge = POMChallenge(msg.sender,target,witness);
    challengeList.push(challenge);
  }

  //每个epoch发送奖励给pom节点
  function sendPomEpochReward(uint256 amount) public onlyMiner{
    uint256 totalbalance = IERC20(meshToken).balanceOf(address(this));
    if (amount > totalbalance || amount ==0 ){
        return;
    }
    uint challengerScoreTotal = 0;
    uint targetScoreTotal = 0;
    uint witnessScoreTotal = 0;
    uint256 challengerMeshReward = amount*6290/10000;
    uint256 targetMeshReward = amount*502/10000;
    uint256 witnessMeshReward = amount*2008/10000;
    //计算三种角色每个角色总分
    for ( uint256 i = 0; i<challengeList.length;i++){
      POMChallenge memory pomChallenge = challengeList[i];
      uint challengerScore = 1;
      uint targetScore = 0;
      uint witnessScore = 0;
      if(pomChallenge.witness.length>0 && pomChallenge.witness.length<4){
          challengerScore = 2;
          targetScore = 1;
          witnessScore = 3;
     }else if(pomChallenge.witness.length>=4 && pomChallenge.witness.length<8){
          challengerScore = 3;
          targetScore = 2;
          witnessScore = 2;
     }else if(pomChallenge.witness.length>8){
          challengerScore = 4;
          targetScore = 3;
          witnessScore = 1;
     }
     challengerScoreTotal += challengerScore;
     targetScoreTotal += targetScore;

     uint witnessLength = pomChallenge.witness.length <=8? pomChallenge.witness.length:8;
     witnessScoreTotal += witnessScore * witnessLength;
    }

   //分配mesh奖励给Challenger,Target,Witness
    for (uint256 i = 0; i<challengeList.length;i++){

      POMChallenge memory pomChallenge = challengeList[i];
      uint challengerScore = 1;
      uint targetScore = 0;
      uint witnessScore = 0;
      if(pomChallenge.witness.length>0 && pomChallenge.witness.length<4){
          challengerScore = 2;
          targetScore = 1;
          witnessScore = 3;
      }else if(pomChallenge.witness.length>=4 && pomChallenge.witness.length<8){
          challengerScore = 3;
          targetScore = 2;
          witnessScore = 2;
      }else if(pomChallenge.witness.length>8){
          challengerScore = 4;
          targetScore = 3;
          witnessScore = 1;
      }
       uint rewardChallenger = challengerMeshReward * challengerScore / challengerScoreTotal;
       IERC20(meshToken).transfer(pomChallenge.challenger, rewardChallenger);

       uint rewardTarget = targetMeshReward * targetScore / targetScoreTotal;
       IERC20(meshToken).transfer(pomChallenge.target, rewardTarget);

       uint witnessLength = pomChallenge.witness.length <=8? pomChallenge.witness.length:8;
       for(uint j = 0; j< witnessLength; j++){
           uint rewardWitness = witnessMeshReward * witnessScore / witnessScoreTotal;
           IERC20(meshToken).transfer(pomChallenge.witness[j], rewardWitness);
       }
    }
    uint256 balance = IERC20(meshToken).balanceOf(address(this));
    if(balance >0){
       IERC20(meshToken).transfer(address(1), balance);
    }
    delete challengeList;
  }
  //获取meshbox列表
  function getMeshBoxList() public view returns(MeshBoxInfo[] memory){

    MeshBoxInfo [] memory pomChallengeList;
    pomChallengeList = new MeshBoxInfo[](meshboxList.length);
    for(uint256 i = 0;i<meshboxList.length;i++){
       address addr = meshboxList[i];
       pomChallengeList[i].id = meshboxMap[addr].id;
       pomChallengeList[i].addr = meshboxMap[addr].addr;
    }
    return pomChallengeList;
  }
  //获取当前epoch中的挑战列表
  function getChallengeList() public view returns(POMChallenge[] memory){
    return challengeList;
  }

}
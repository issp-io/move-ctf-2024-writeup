# MoveCTF 2024 Writeup

## Checkin

```
public entry fun get_flag(string: vector<u8>, ctx: &mut TxContext) {  
	assert!(string == b"MoveBitCTF",ESTRING);  
	event::emit(Flag {  
		sender: tx_context::sender(ctx),  
			flag: true,  
	});  
}
```

According to the function, we can know that we have to call the function with arg `MoveBitCTF`.

```
$ sui client call --package 0xc2710da18f4e90f07f6066a1500565bd32af3194134865c8698f80c950c1162f --module checkin --function get_flag --gas-budget 10000000 --args MoveBitCTF
```

# dynamic_matrix_traversal
Two layers of for loop were used to traverse the values of m and n. js was used to simulate the logic of move, and the conditional number pairs [89, 5] and [169, 3] were traversed. The two sets of data were consistent with the results


## Swap

Upon analyzing the code, we can determine that the vault is initially initialized with 100 coin_a and 100 coin_b. Additionally, 10 coin_a and 10 coin_b are sent to us. To obtain the flag, we must ensure that the balance of coin_a and coin_b in the vault becomes 0.

Typically, we lack sufficient coin_a and coin_b to completely deplete the vault. However, we can utilize a flash loan to borrow either coin_a or coin_b from the vault and then repay the loan within the same transaction. Borrowing coins from the vault alters the balance of coin_a and coin_b within the vault, thereby impacting the amount of coin we can swap for an equivalent quantity of coin.

The simplest approach to solve this challenge involves borrowing 90 coin_b from the vault, which leaves 10 coin_b and 100 coin_a in the vault. Subsequently, we can swap 10 coin_b for 100 coin_a, effectively emptying the coin_a in the vault. Next, we can repay the 90 coin_b borrowed from the vault, resulting in 0 coin_a and 110 coin_b remaining in the vault. Following this, we can borrow 110 coin_b from the vault, effectively depleting the coin_b in the vault. Finally, we can invoke the `get_flag` function to obtain the flag and subsequently repay the 110 coin_b.

The solve function is as follows:

```
public fun solve<A, B>(vault: &mut Vault<A,B>, coinb10: Coin<B>, ctx: &mut TxContext) {
    let (coina0, coinb90, receipt) = vault::flash(vault, 90, true, ctx);
    let coina100 = swap_b_to_a(vault, coinb10, ctx);
    repay_flash(vault, coina0, coinb90, receipt);
    let (coina0, coinb110, receipt2) = vault::flash(vault, 110, true, ctx);
    get_flag(vault, ctx);
    repay_flash(vault, coina0, coinb110, receipt2);
    public_transfer(coina100, sender(ctx));
}
```

## subset

After analyzing the code, we can determine that the challenge is a classic subset sum problem.
We are given a set of numbers, a target sum and a target count.
Our objective is to find the subset of the given set that sums to the target sum and have the target count.

The first two problems of this question, SUBSET1 and SUBSET2, can use brute force search to directly produce results, not to go into details, the difficulty is the third problem, SUBSET3, the efficiency of direct brute force search is too low

SUBSET3 uses recursive deep search + pruning optimization + memory array cache, and can produce results in 10 minutes

Suppose that the array of raw data is s = SUBSET3, SUBSET3_k == 10, define two two-dimensional arrays to cache data, `maxSumStartIndexToTail[index][n]`, `minSumStartIndexToTail[index][n]`

// `maxSumStartIndexToTail[2][5]` Indicates the maximum five numbers that can be accumulated from the element starting with index 2 to the end of the data
// `minSumStartIndexToTail[0][4]` Indicates the minimum four numbers accumulated from the element starting with index 0 to the end of the data
All the data of these two two-dimensional arrays can be solved by iterating through the for loop, which can be solved within o(n^3) time complexity

The following is the core code of deep search, startIndex means to search from the index of the S-array, targetCounts means to search from the start of startIndex to the end of the S-array, select targetCounts element,
So we can know the initial state of search from 0 (0, 10) element Look behind to 10 element, whether the final accumulative results equal to SUBSET3_SUM (9639405868465735216305592265916);
If find it, print the current solution path

The core is two pruning optimizations if (currentSum + `maxSumStartIndexToTail[startIndex][targetCounts]` < target) indicates that it is impossible to find the target SUBSET3_SUM from this search tree, and the search is abandoned
if (currentSum + `minSumStartIndexToTail[startIndex][targetCounts]` >  target indicates that if the search tree goes down, the target SUBSET3_SUM cannot be found

So far these two optimizations can be solved in 1 hour
If you want to optimize it further, you can add a cache array, `f[i][targetCounts][sum]` means from 0... i elements extract targetCounts element, sum result is whether sum already exists, cached, without repeated search has found `f[i][targetCounts][sum]` search state tree, can be solved in 5 minutes
 
```
const search = (startIndex: number, targetCounts: number) => {
    // found result
    if (result > 0n && resultIndexes.length > 0) {
        return;
    }

    // optimize pruning deep search
    if (currentSum > target) {
        return;
    }
    // optimize pruning deep search
    if (currentSum + maxSumStartIndexToTail[startIndex][targetCounts] < target) {
        return;
    }
    // optimize pruning deep search
    if (currentSum + minSumStartIndexToTail[startIndex][targetCounts] > target) {
        return;
    }


    // check result
    if (targetCounts === 0) {
        if (currentSum === target) {
            log('success', result, target, 'currentIndexesForS = ', currentIndexesForS);
            result = currentSum;
            resultIndexes = currentIndexesForS;
        }
        return;
    }

    //  exceed search array
    if (targetCounts === 0 || startIndex >= s_len) return;

    // for loop to search current index
    for (let i = startIndex; i <= s_len - targetCounts; i++) {
        currentIndexesForS.push(i);
        currentSum += s[i];

        if (targetCounts > 0) {
            search(i + 1, targetCounts - 1);
        }

        currentSum -= s[i];
        currentIndexesForS.pop();
    }
};

```



## zk1
The computation represented by `zk1.circom` is: `c = a * b`, `a <= 2^252 and b <= 2^252`and `c = 58567186824402957966382507182680956225095467533943200425018625513920465170743`. The zk proof system is based on BN254 curve, the order of BN254 curve is `p = 21888242871839275222246405745257275088548364400416034343698204186575808495617`. The `public input c` actually equals to `c % p = 14790701080724407521889695692166406047998738733111131737622217140768848179509`. So prover needs to solve `a` and `b` according `c = a * b`; we can use the sage codes to brute force to get a pair of `a = 17` and `b = 870041240042612207169982099539200355764631690183007749271895125927579304677`. Then using the following codes to get serialized input and proof:
```rust
use std::str::FromStr;

use ark_bn254::Bn254;
use ark_circom::CircomBuilder;
use ark_circom::CircomConfig;
use ark_groth16::Groth16;
use ark_groth16::ProvingKey;
use ark_serialize::CanonicalDeserialize;
use ark_snark::SNARK;
use num_bigint::BigInt;
use ark_serialize::CanonicalSerialize;

fn hex_string_to_bytes(hex_string: &str) -> Vec<u8> {
    hex::decode(hex_string).unwrap_or_else(|e| {
        panic!("Failed to decode hex string: {}", e);
    })
}

fn main() {
    let compressed_pk = "";  // copy serialized proving key to here

    let raw_pk = hex_string_to_bytes(compressed_pk);
    println!("size is {}", raw_pk.len());

    // Load the WASM and R1CS for witness and proof generation
    let cfg = CircomConfig::<Bn254>::new("zk2.wasm", "zk2.r1cs").unwrap();

    // Insert our secret inputs as key value pairs. We insert a single input, namely the input to the hash function.
    let mut builder = CircomBuilder::new(cfg);
    let t = BigInt::from_str("870041240042612207169982099539200355764631690183007749271895125927579304677").unwrap();
    builder.push_input("a", 17);

    builder.push_input("b", t);

    // Create an empty instance for setting it up
    let circom = builder.setup();

    // WARNING: The code below is just for debugging, and should instead use a verification key generated from a trusted setup.
    // See for example https://docs.circom.io/getting-started/proving-circuits/#powers-of-tau.
    let mut rng = rand::thread_rng();
    // let params =
    // Groth16::<Bn254>::generate_random_parameters_with_reduction(circom, &mut rng).unwrap();

    let cursor = std::io::Cursor::new(raw_pk);
    let params = ProvingKey::<Bn254>::deserialize_compressed(cursor).unwrap();
    let mut vk_2 = Vec::new();
    params.vk.serialize_compressed(&mut vk_2).unwrap();
    let vk_hex = hex::encode(vk_2);
    println!("vk is {}", vk_hex);

    let circom = builder.build().unwrap();

    // There's only one public input, namely the hash digest.
    let inputs = circom.get_public_inputs().unwrap();

    // Generate the proof
    let proof = Groth16::<Bn254>::prove(&params, circom, &mut rng).unwrap();

    // Check that the proof is valid
    let pvk = Groth16::<Bn254>::process_vk(&params.vk).unwrap();
    let verified = Groth16::<Bn254>::verify_with_processed_vk(&pvk, &inputs, &proof).unwrap();
    assert!(verified);
    println!("verification result {}", verified);

    let mut proof_inputs_bytes = Vec::new();
    for input in inputs.iter() {
        input.serialize_compressed(&mut proof_inputs_bytes).unwrap();
    }

    let mut proof_points_bytes = Vec::new();
    proof.a.serialize_compressed(&mut proof_points_bytes).unwrap();
    proof.b.serialize_compressed(&mut proof_points_bytes).unwrap();
    proof.c.serialize_compressed(&mut proof_points_bytes).unwrap();

    let proof_inputs_hex = hex::encode(proof_inputs_bytes);
    let proo_hex = hex::encode(proof_points_bytes);
    println!("input is {}", proof_inputs_hex);
    println!("proof is {}", proo_hex);
}
```


The solution code is as follows:

```
public fun solve(ctx: &mut TxContext) {
    zk1::verify_proof(
        x"35710bd4f6134564b803634c73141b660390b447ef68de09c8204d377a3db320",
x"63f86fbcd8b7630ff899714ed597635d8f7762d1bf94dea232de97a9e6678128c6e3c699e3086bf1bec5a1431bbf5a27fb74e7dd8b285ee30e39e7949bb720154f2fc5e78e7d2e1be5c0023190abf2dcfccc961dd7fc48c1c13b40664c5281af02124166abd4aa5079e99fb926d4e4a7e02cd83c02fc95096f51080bc7077dab",
        ctx);
}
```

## easygame
Try out a few numbers by hand, [6,4,3] is ok 


## kitchen

After analyzing the code, it is evident that the challenge is related to BCS serialization. Our objective is to obtain the serialized data of a particular struct and create an object that matches the given data.

Upon reviewing the specification (available at [this link](https://github.com/diem/bcs#binary-canonical-serialization-bcs)), it is clear that we can easily perform the serialization and deserialization manually for this challenge.

The solution is outlined below:

```
public fun solve(ctx: &mut TxContext) {
    let status = get_status(ctx);
    // 04
    // 15a5
    // b8a6
    // f8c9
    // 46bb
    // 03
    // 00bd
    // 9d99
    // 7eb7
    // 03
    // 8ad7
    // 84fa
    // f2b8
    // 02
    // c5f1
    // 22e1
    let olive_oils = vector<Olive_oil>[
        get_Olive_oil(0xa515),
        get_Olive_oil(0xa6b8),
        get_Olive_oil(0xc9f8),
        get_Olive_oil(0xbb46),
    ];
    let yeast = vector<Yeast>[
        get_Yeast(0xbd00),
        get_Yeast(0x999d),
        get_Yeast(0xb77e),
    ];
    let flour = vector<Flour>[
        get_Flour(0xd78a),
        get_Flour(0xfa84),
        get_Flour(0xb8f2),
    ];
    let salt = vector<Salt>[
        get_Salt(0xf1c5),
        get_Salt(0xe122),
    ];
    cook(olive_oils, yeast, flour, salt, &mut status);
    recook(x"06d9b954eb6892f7c5eca184d00400bd81fc9d997eb705c7dc7acc198fb1966d8a03018bc5f1ecc6", &mut status);
    get_flag(&status, ctx);
}
```

## zk2
The computation represented by `zk1.circom` is: `168700* x^2 + delta^2 = 1 + 168696 * x^2 * delta^2`, `x <= 2^252`and the public input is `y = delta`. Using the sage codes to brute force to get the `x = 3018630044909800347603380482417762234672414469140857941474959316564705257709`and `delta = 5`. Then using the following codes to get serialized input and proof:
```rust
use std::str::FromStr;

use ark_bn254::Bn254;
use ark_circom::CircomBuilder;
use ark_circom::CircomConfig;
use ark_groth16::Groth16;
use ark_groth16::ProvingKey;
use ark_serialize::CanonicalDeserialize;
use ark_snark::SNARK;
use num_bigint::BigInt;
use ark_serialize::CanonicalSerialize;

fn hex_string_to_bytes(hex_string: &str) -> Vec<u8> {
    hex::decode(hex_string).unwrap_or_else(|e| {
        panic!("Failed to decode hex string: {}", e);
    })
}

fn main() {
    let compressed_pk = "";
    
    let raw_pk = hex_string_to_bytes(compressed_pk);
    println!("size is {}", raw_pk.len());
    
    // Load the WASM and R1CS for witness and proof generation
    let cfg = CircomConfig::<Bn254>::new("zk2.wasm", "zk2.r1cs").unwrap();

    // Insert our secret inputs as key value pairs. We insert a single input, namely the input to the hash function.
    let mut builder = CircomBuilder::new(cfg);
    let t = BigInt::from_str("3018630044909800347603380482417762234672414469140857941474959316564705257709").unwrap();
    builder.push_input("x", t);
    
    builder.push_input("delta", 5);

    // Create an empty instance for setting it up
    let circom = builder.setup();

    // WARNING: The code below is just for debugging, and should instead use a verification key generated from a trusted setup.
    // See for example https://docs.circom.io/getting-started/proving-circuits/#powers-of-tau.
    let mut rng = rand::thread_rng();
    // let params =
        // Groth16::<Bn254>::generate_random_parameters_with_reduction(circom, &mut rng).unwrap();

    let cursor = std::io::Cursor::new(raw_pk);
    let params = ProvingKey::<Bn254>::deserialize_compressed(cursor).unwrap();
    let mut vk_2 = Vec::new();
    params.vk.serialize_compressed(&mut vk_2).unwrap();
    let vk_hex = hex::encode(vk_2);
    println!("vk is {}", vk_hex);

    let circom = builder.build().unwrap();

    // There's only one public input, namely the hash digest.
    let inputs = circom.get_public_inputs().unwrap();

    // Generate the proof
    let proof = Groth16::<Bn254>::prove(&params, circom, &mut rng).unwrap();

    // Check that the proof is valid
    let pvk = Groth16::<Bn254>::process_vk(&params.vk).unwrap();
    let verified = Groth16::<Bn254>::verify_with_processed_vk(&pvk, &inputs, &proof).unwrap();
    assert!(verified);
    println!("verification result {}", verified);

    let mut proof_inputs_bytes = Vec::new();
    inputs.serialize_compressed(&mut proof_inputs_bytes).unwrap();

    let mut proof_points_bytes = Vec::new();
    proof.a.serialize_compressed(&mut proof_points_bytes).unwrap();
    proof.b.serialize_compressed(&mut proof_points_bytes).unwrap();
    proof.c.serialize_compressed(&mut proof_points_bytes).unwrap();
    
    let mut proof_points_bytes2 = Vec::new();
    for input in inputs.iter() {
        input.serialize_compressed(&mut proof_inputs_bytes).unwrap();
    }

    let proof_inputs_hex = hex::encode(proof_inputs_bytes);
    let proo_hex = hex::encode(proof_points_bytes);
    println!("input is {}", proof_inputs_hex);
    println!("proof is {}", proo_hex);

    let proo_hex2 = hex::encode(proof_points_bytes2);  
    println!("proof is {}", proo_hex2);

}
```




## OtterHub

After analyze the transactions of the package, we can know that there are three commits made in the second repo. And the content of the commits are bytes not readable.

The hex format of the commits are as follows:

```
a11ceb0b0600000007010002030205050701070815081d20063db2010cef0111000000010000000009656e63727970746f720a73746f72655f6261627900000000000000000000000000000000000000000000000000000000000000000a025655585858585858585858585858585858585858585858585858585858585858585858585858585858585858585858585858585858585858585858585858585858585858585858585858585858585858585858585858580a0256550a0d061c367d46456c1d3b0d47505354576c2846065f595f31127d46456c1d3b4e04505354576c2846451c585858585858585858585858585858585858585858585858585858585858585858585858585858585858000100000003060300000000000000010200

a11ceb0b060000000701000203020505071a0721150836200656590caf018d0100000001000000000a0a020a020a02070a020a020a02060a02070a02030a02010209656e63727970746f720a73746f72655f6261627900000000000000000000000000000000000000000000000000000000000000000a025655585858585858585858585858585858585858585858585858585858585858585858585858585858585858585858585858585858585858585858585858585858585858585858585858585858585858585858585858580001000001360601000000000000000c08400200000000000000000c0907000c000a080e004102230424050c0d090c0307000c0107000c020b030e010a084202140e020a08060100000000000000174202141d44020b08060100000000000000160c0805040d090c0707000c050e050c0607000c040b070b060e0441020601000000000000001742021444020200

a11ceb0b0600000007010002030205050701070815081d20063db2010cef0111000000010000000009656e63727970746f720a73746f72655f6261627900000000000000000000000000000000000000000000000000000000000000000a025655585858585858585858585858585858585858585858585858585858585858585858585858585858585858585858585858585858585858585858585858585858585858585858585858585858585858585858585858580a02565558585858585858585858585858585858585858585858585858585858585858585858585858585858585858595f310d274002681d3b0d47505354576c2846065f595f31120c020b01070b1a1d3b0d47505354574e7d000100000003060300000000000000010200
```

The bytes in the start show that they are move bytecode.

After decompile the bytecode, we can get the following code in the second commit.

```
// Move bytecode v6
module e98bb91f8043b5bd68c7011afb4b1a8484c3855faa195c303a8b3fd87f295715.encryptor {


public store_baby() {
L0:	loc0: vector<u8>
L1:	loc1: vector<u8>
L2:	loc2: vector<u8>
L3:	loc3: &mut vector<u8>
L4:	loc4: vector<u8>
L5:	loc5: vector<u8>
L6:	loc6: &vector<u8>
L7:	loc7: &mut vector<u8>
L8:	loc8: u64
L9:	loc9: vector<u8>
B0:
	0: LdU64(1)
	1: StLoc[8](loc8: u64)
	2: VecPack(2, 0)
	3: StLoc[9](loc9: vector<u8>)
B1:
	4: LdConst[0](Vector(U8): 55585858..)
	5: StLoc[0](loc0: vector<u8>)
	6: CopyLoc[8](loc8: u64)
	7: ImmBorrowLoc[0](loc0: vector<u8>)
	8: VecLen(2)
	9: Lt
	10: BrFalse(36)
B2:
	11: Branch(12)
B3:
	12: MutBorrowLoc[9](loc9: vector<u8>)
	13: StLoc[3](loc3: &mut vector<u8>)
	14: LdConst[0](Vector(U8): 55585858..)
	15: StLoc[1](loc1: vector<u8>)
	16: LdConst[0](Vector(U8): 55585858..)
	17: StLoc[2](loc2: vector<u8>)
	18: MoveLoc[3](loc3: &mut vector<u8>)
	19: ImmBorrowLoc[1](loc1: vector<u8>)
	20: CopyLoc[8](loc8: u64)
	21: VecImmBorrow(2)
	22: ReadRef
	23: ImmBorrowLoc[2](loc2: vector<u8>)
	24: CopyLoc[8](loc8: u64)
	25: LdU64(1)
	26: Sub
	27: VecImmBorrow(2)
	28: ReadRef
	29: Xor
	30: VecPushBack(2)
	31: MoveLoc[8](loc8: u64)
	32: LdU64(1)
	33: Add
	34: StLoc[8](loc8: u64)
	35: Branch(4)
B4:
	36: MutBorrowLoc[9](loc9: vector<u8>)
	37: StLoc[7](loc7: &mut vector<u8>)
	38: LdConst[0](Vector(U8): 55585858..)
	39: StLoc[5](loc5: vector<u8>)
	40: ImmBorrowLoc[5](loc5: vector<u8>)
	41: StLoc[6](loc6: &vector<u8>)
	42: LdConst[0](Vector(U8): 55585858..)
	43: StLoc[4](loc4: vector<u8>)
	44: MoveLoc[7](loc7: &mut vector<u8>)
	45: MoveLoc[6](loc6: &vector<u8>)
	46: ImmBorrowLoc[4](loc4: vector<u8>)
	47: VecLen(2)
	48: LdU64(1)
	49: Sub
	50: VecImmBorrow(2)
	51: ReadRef
	52: VecPushBack(2)
	53: Ret
}

Constants [
	0 => vector<u8>: "XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX" // interpreted as UTF8 string
]
```

Translating the bytecode to Move source code, we can get the following code.

```
public fun encrypt() {
    let loc0: vector<u8>;
    let loc1: vector<u8>;
    let loc2: vector<u8>;
    let loc3: &mut vector<u8>;
    let loc4: vector<u8>;
    let loc5: vector<u8>;
    let loc6: &vector<u8>;
    let loc7: &mut vector<u8>;
    let loc8: u64;
    let loc9: vector<u8>;

    loc8 = 1;
    loc9 = vector::empty<u8>();

    loc0 = CON;

    while (loc8 < vector::length(&loc0)) {
        loc3 = &mut loc9;
        loc1 = CON;
        loc2 = CON;
        vector::push_back(loc3, *vector::borrow(&loc1, loc8) ^ *vector::borrow(&loc2, loc8 - 1));
        loc8 = loc8 + 1;
    };

    loc7 = &mut loc9;
    loc5 = CON;
    loc6 = &loc5;
    loc4 = CON;
    vector::push_back(loc7, *vector::borrow(&loc4, vector::length(loc6) - 1 ));
}
```

The code demonstrates a basic XOR encryption. Decrypting the encrypted data will reveal the flag.

Upon reviewing the other two commits, we discovered two distinct sets of encrypted data in the first and third commit.

Decrypting the data yields the following flag: `flag{M0v3_Byt3c0d3_w17h1n_M0v3_By73c0d3_w1th1n_Ru57_Byt3c0d3_w17h1n_MACHINE_Byt3c0d3}`.

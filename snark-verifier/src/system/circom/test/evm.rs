use std::rc::Rc;

use crate::{
    loader::{
        evm::{self, encode_calldata, EvmLoader, Address, ExecutorBuilder},
        native::NativeLoader,
    },
    pcs::kzg::{Gwc19, KzgAs, LimbsEncoding},
    system::circom::{
        compile, test::testdata::TESTDATA_EVM, Proof,
        PublicSignals, VerifyingKey, transcript::evm::EvmTranscript,
    },
    verifier::{self, SnarkVerifier},
};
use halo2_curves::bn256::{Bn256, Fq, Fr, G1Affine};

const LIMBS: usize = 4;
const BITS: usize = 68;

type Plonk = verifier::plonk::PlonkVerifier<KzgAs<Bn256, Gwc19>>;
type PlonkVerifier = verifier::plonk::PlonkVerifier<KzgAs<Bn256, Gwc19>, LimbsEncoding<LIMBS, BITS>>;

#[test]
fn test() {
    let vk: VerifyingKey<Bn256> = serde_json::from_str(TESTDATA_EVM.vk).unwrap();
    let g1 = vk.svk();
    let (g2, s_g2) = vk.dk();
    let dk = (g1, g2, s_g2).into();

    let protocol = compile(&vk);

    let [public_signal] = TESTDATA_EVM.public_signals.map(|public_signals| {
        serde_json::from_str::<PublicSignals<Fr>>(public_signals)
            .unwrap()
            .to_vec()
    });
    let [proof] = TESTDATA_EVM.proofs.map(|proof| {
        serde_json::from_str::<Proof<Bn256>>(proof)
            .unwrap()
            .to_uncompressed_be()
    });

    {
        let instances = [public_signal.clone()];
        let mut transcript = EvmTranscript::<G1Affine, NativeLoader, _, _>::new(proof.as_slice());
        let proof = Plonk::read_proof(&dk, &protocol, &instances, &mut transcript).unwrap();
        matches!(Plonk::verify(&dk, &protocol, &instances, &proof), Ok(_));
    }

    let deployment_code = {
        let loader = EvmLoader::new::<Fq, Fr>();
        let protocol = protocol.loaded(&loader);
        let mut transcript = EvmTranscript::<G1Affine, Rc<EvmLoader>, _, _>::new(&loader);
        let instances = transcript.load_instances(vec![public_signal.len()]);
        let proof = PlonkVerifier::read_proof(&dk, &protocol, &instances, &mut transcript).unwrap();
        PlonkVerifier::verify(&dk, &protocol, &instances, &proof).unwrap();
        evm::compile_yul(&loader.yul_code())
    };

    let calldata = encode_calldata(&[public_signal.clone()], &proof);
    let success = {
        let mut evm = ExecutorBuilder::default()
            .with_gas_limit(u64::MAX.into())
            .build();

        let caller = Address::from_low_u64_be(0xfe);
        let verifier = evm
            .deploy(caller, deployment_code.into(), 0.into())
            .address
            .unwrap();
        let result = evm.call_raw(caller, verifier, calldata.into(), 0.into());

        dbg!(result.gas_used);
        dbg!(result.exit_reason);
        !result.reverted
    };
    assert!(success);
}

use pallet_evm::{Precompile, PrecompileHandle, PrecompileResult, PrecompileSet};
use sp_core::H160;
use sp_std::marker::PhantomData;

use pallet_evm_precompile_modexp::Modexp;
use pallet_evm_precompile_sha3fips::Sha3FIPS256;
use pallet_evm_precompile_simple::{ECRecover, ECRecoverPublicKey, Identity, Ripemd160, Sha256};

use {
	alloc::{format, vec::Vec},
	czk_precompiles::{AnemioJave381Input4, AnonymousTransactionVerifier},
	fp_evm::{ExitError, ExitSucceed, LinearCostPrecompile, PrecompileFailure},
};

pub struct FrontierPrecompiles<R>(PhantomData<R>);

impl<R> FrontierPrecompiles<R>
where
	R: pallet_evm::Config,
{
	pub fn new() -> Self {
		Self(Default::default())
	}
	pub fn used_addresses() -> [H160; 7] {
		[
			hash(1),
			hash(2),
			hash(3),
			hash(4),
			hash(5),
			hash(1024),
			hash(1025),
			hash(5000),
			hash(5001),
		]
	}
}
impl<R> PrecompileSet for FrontierPrecompiles<R>
where
	R: pallet_evm::Config,
{
	fn execute(&self, handle: &mut impl PrecompileHandle) -> Option<PrecompileResult> {
		match handle.code_address() {
			// Ethereum precompiles :
			a if a == hash(1) => Some(ECRecover::execute(handle)),
			a if a == hash(2) => Some(Sha256::execute(handle)),
			a if a == hash(3) => Some(Ripemd160::execute(handle)),
			a if a == hash(4) => Some(Identity::execute(handle)),
			a if a == hash(5) => Some(Modexp::execute(handle)),
			// Non-Frontier specific nor Ethereum precompiles :
			a if a == hash(1024) => Some(Sha3FIPS256::execute(handle)),
			a if a == hash(1025) => Some(ECRecoverPublicKey::execute(handle)),
			a if a == hash(5000) => Some(AnemoiJive::execute(handle)),
			a if a == hash(5001) => Some(AnonymousVerifier::execute(handle)),
			_ => None,
		}
	}

	fn is_precompile(&self, address: H160) -> bool {
		Self::used_addresses().contains(&address)
	}
}

fn hash(a: u64) -> H160 {
	H160::from_low_u64_be(a)
}

pub struct AnemoiJive;

impl LinearCostPrecompile for AnemoiJive {
	const BASE: u64 = 3000;
	const WORD: u64 = 0;
	fn execute(input: &[u8], _: u64) -> Result<(ExitSucceed, Vec<u8>), PrecompileFailure> {
		let jave = AnemioJave381Input4::new().map_err(|e| PrecompileFailure::Error {
			exit_status: ExitError::Other(format!("{:?}", e).into()),
		})?;
		jave.call(input)
			.map(|output| (ExitSucceed::Stopped, output))
			.map_err(|e| PrecompileFailure::Error {
				exit_status: ExitError::Other(
					alloc::format!("AnemioJave381Input4 call error:{:?}", e).into(),
				),
			})
	}
}

pub struct AnonymousVerifier;

impl LinearCostPrecompile for AnonymousVerifier {
	const BASE: u64 = 3000;
	const WORD: u64 = 0;
	fn execute(input: &[u8], _: u64) -> Result<(ExitSucceed, Vec<u8>), PrecompileFailure> {
		let jave = AnonymousTransactionVerifier::new().map_err(|e| PrecompileFailure::Error {
			exit_status: ExitError::Other(format!("{:?}", e).into()),
		})?;
		jave.call(input)
			.map(|output| (ExitSucceed::Stopped, output))
			.map_err(|e| PrecompileFailure::Error {
				exit_status: ExitError::Other(
					format!("AnonymousTransactionVerifier call error:{:?}", e).into(),
				),
			})
	}
}

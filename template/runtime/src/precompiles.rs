use pallet_evm::{Precompile, PrecompileHandle, PrecompileResult, PrecompileSet};
use sp_core::H160;
use sp_std::marker::PhantomData;

use pallet_evm_precompile_modexp::Modexp;
use pallet_evm_precompile_sha3fips::Sha3FIPS256;
use pallet_evm_precompile_simple::{ECRecover, ECRecoverPublicKey, Identity, Ripemd160, Sha256};
use {
	crate::Vec,
	core::ptr,
	fp_evm::{ExitError, ExitSucceed, LinearCostPrecompile, PrecompileFailure},
	scale_info::prelude::{format, string::String},
};

pub struct FrontierPrecompiles<R>(PhantomData<R>);

impl<R> FrontierPrecompiles<R>
where
	R: pallet_evm::Config,
{
	pub fn new() -> Self {
		Self(Default::default())
	}
	pub fn used_addresses() -> [H160; 9] {
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
			a if a == hash(1) => Some(<ECRecover as Precompile>::execute(handle)),
			a if a == hash(2) => Some(<Sha256 as Precompile>::execute(handle)),
			a if a == hash(3) => Some(<Ripemd160 as Precompile>::execute(handle)),
			a if a == hash(4) => Some(<Identity as Precompile>::execute(handle)),
			a if a == hash(5) => Some(<Modexp as Precompile>::execute(handle)),
			// Non-Frontier specific nor Ethereum precompiles :
			a if a == hash(1024) => Some(<Sha3FIPS256 as Precompile>::execute(handle)),
			a if a == hash(1025) => Some(<ECRecoverPublicKey as Precompile>::execute(handle)),
			a if a == hash(5000) => Some(<AnemoiJive as Precompile>::execute(handle)),
			a if a == hash(5001) => Some(<AnonymousVerifier as Precompile>::execute(handle)),
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
	const BASE: u64 = 0;
	const WORD: u64 = 0;
	fn execute(
		input: &[u8],
		_: u64,
	) -> core::result::Result<(ExitSucceed, Vec<u8>), PrecompileFailure> {
		let input_len = input.len();
		let input_data: Vec<u8> = Vec::with_capacity(input_len);
		unsafe {
			ptr::copy_nonoverlapping(input[0] as *mut u8, input_data[0] as *mut u8, input_len)
		};
		let output_len = 1024;
		let output: Vec<u8> = Vec::with_capacity(output_len);
		let error_info_len = 1024;
		let error_info: Vec<u8> = Vec::with_capacity(error_info_len);
		let ret = unsafe {
			czk_precompiles::call_anemoi_jive381(
				input_data[0] as *mut u8,
				input_len as u32,
				output[0] as *mut u8,
				output_len as u32,
				error_info[0] as *mut u8,
				error_info_len as u32,
			)
		};
		if ret < 0 {
			Err(PrecompileFailure::Error {
				exit_status: ExitError::Other(
					format!(
						"call_anemoi_jive381 error:{:?}",
						String::from_utf8_lossy(&error_info)
					)
					.into(),
				),
			})
		} else {
			Ok((ExitSucceed::Stopped, output))
		}
	}
}

pub struct AnonymousVerifier;

impl LinearCostPrecompile for AnonymousVerifier {
	const BASE: u64 = 0;
	const WORD: u64 = 0;
	fn execute(
		input: &[u8],
		_: u64,
	) -> core::result::Result<(ExitSucceed, Vec<u8>), PrecompileFailure> {
		let input_len = input.len();
		let input_data: Vec<u8> = Vec::with_capacity(input_len);
		unsafe {
			ptr::copy_nonoverlapping(input[0] as *mut u8, input_data[0] as *mut u8, input_len)
		};
		let output_len = 1024;
		let output: Vec<u8> = Vec::with_capacity(output_len);
		let error_info_len = 1024;
		let error_info: Vec<u8> = Vec::with_capacity(error_info_len);
		let ret = unsafe {
			czk_precompiles::call_anonymous_transaction_verifier(
				input_data[0] as *mut u8,
				input_len as u32,
				output[0] as *mut u8,
				output_len as u32,
				error_info[0] as *mut u8,
				error_info_len as u32,
			)
		};
		if ret < 0 {
			Err(PrecompileFailure::Error {
				exit_status: ExitError::Other(
					format!(
						"call_anemoi_jive381 error:{:?}",
						String::from_utf8_lossy(&error_info)
					)
					.into(),
				),
			})
		} else {
			Ok((ExitSucceed::Stopped, output))
		}
	}
}
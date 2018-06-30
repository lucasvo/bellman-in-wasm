#![feature(proc_macro, wasm_custom_section, wasm_import_module)]
extern crate bellman;
extern crate pairing;
extern crate rand;
extern crate wasm_bindgen;
use wasm_bindgen::prelude::*;

// For randomness (during paramgen and proof generation)
use rand::Rng;

#[wasm_bindgen]
extern "C" {
    #[wasm_bindgen(js_namespace = console)]
    fn log(msg: &str);
}

// Bring in some tools for using pairing-friendly curves
use pairing::{
    Engine,
    Field
};

// We're going to use the BLS12-381 pairing-friendly elliptic curve.
use pairing::bls12_381::{
    Bls12
};

// We'll use these interfaces to construct our circuit.
use bellman::{
    Circuit,
    ConstraintSystem,
    SynthesisError,
};
//    Proof,
    //generate_random_parameters,
    //prepare_verifying_key,
    //create_random_proof,
//    verify_proof,
//};

const MIMC_ROUNDS: usize = 322;

/// This is an implementation of MiMC, specifically a
/// variant named `LongsightF322p3` for BLS12-381.
/// See http://eprint.iacr.org/2016/492 for more 
/// information about this construction.
///
/// ```
/// function LongsightF322p3(xL ⦂ Fp, xR ⦂ Fp) {
///     for i from 0 up to 321 {
///         xL, xR := xR + (xL + Ci)^3, xL
///     }
///     return xL
/// }
/// ```
fn mimc<E: Engine>(
    mut xl: E::Fr,
    mut xr: E::Fr,
    constants: &[E::Fr]
) -> E::Fr
{
    assert_eq!(constants.len(), MIMC_ROUNDS);

    for i in 0..MIMC_ROUNDS {
        let mut tmp1 = xl;
        tmp1.add_assign(&constants[i]);
        let mut tmp2 = tmp1;
        tmp2.square();
        tmp2.mul_assign(&tmp1);
        tmp2.add_assign(&xr);
        xr = xl;
        xl = tmp2;
    }

    xl
}

/// This is our demo circuit for proving knowledge of the
/// preimage of a MiMC hash invocation.
struct MiMCDemo<'a, E: Engine> {
    xl: Option<E::Fr>,
    xr: Option<E::Fr>,
    constants: &'a [E::Fr]
}

/// Our demo circuit implements this `Circuit` trait which
/// is used during paramgen and proving in order to
/// synthesize the constraint system.
impl<'a, E: Engine> Circuit<E> for MiMCDemo<'a, E> {
    fn synthesize<CS: ConstraintSystem<E>>(
        self,
        cs: &mut CS
    ) -> Result<(), SynthesisError>
    {
        assert_eq!(self.constants.len(), MIMC_ROUNDS);

        // Allocate the first component of the preimage.
        let mut xl_value = self.xl;
        let mut xl = cs.alloc(|| "preimage xl", || {
            xl_value.ok_or(SynthesisError::AssignmentMissing)
        })?;

        // Allocate the second component of the preimage.
        let mut xr_value = self.xr;
        let mut xr = cs.alloc(|| "preimage xr", || {
            xr_value.ok_or(SynthesisError::AssignmentMissing)
        })?;

        for i in 0..MIMC_ROUNDS {
            // xL, xR := xR + (xL + Ci)^3, xL
            let cs = &mut cs.namespace(|| format!("round {}", i));

            // tmp = (xL + Ci)^2
            let mut tmp_value = xl_value.map(|mut e| {
                e.add_assign(&self.constants[i]);
                e.square();
                e
            });
            let mut tmp = cs.alloc(|| "tmp", || {
                tmp_value.ok_or(SynthesisError::AssignmentMissing)
            })?;

            cs.enforce(
                || "tmp = (xL + Ci)^2",
                |lc| lc + xl + (self.constants[i], CS::one()),
                |lc| lc + xl + (self.constants[i], CS::one()),
                |lc| lc + tmp
            );

            // new_xL = xR + (xL + Ci)^3
            // new_xL = xR + tmp * (xL + Ci)
            // new_xL - xR = tmp * (xL + Ci)
            let mut new_xl_value = xl_value.map(|mut e| {
                e.add_assign(&self.constants[i]);
                e.mul_assign(&tmp_value.unwrap());
                e.add_assign(&xr_value.unwrap());
                e
            });

            let mut new_xl = if i == (MIMC_ROUNDS-1) {
                // This is the last round, xL is our image and so
                // we allocate a public input.
                cs.alloc_input(|| "image", || {
                    new_xl_value.ok_or(SynthesisError::AssignmentMissing)
                })?
            } else {
                cs.alloc(|| "new_xl", || {
                    new_xl_value.ok_or(SynthesisError::AssignmentMissing)
                })?
            };

            cs.enforce(
                || "new_xL = xR + (xL + Ci)^3",
                |lc| lc + tmp,
                |lc| lc + xl + (self.constants[i], CS::one()),
                |lc| lc + new_xl - xr
            );

            // xR = xL
            xr = xl;
            xr_value = xl_value;

            // xL = new_xL
            xl = new_xl;
            xl_value = new_xl_value;
        }

        Ok(())
    }
}

#[wasm_bindgen]
pub fn run_mimc() {
    // Obviously not safe
    let rng = &mut rand::ChaChaRng::new_unseeded();
    let constants = (0..MIMC_ROUNDS).map(|_| rng.gen()).collect::<Vec<_>>();
    let cs = &mut Namespace{};
    // Create parameters for our circuit
    let c = MiMCDemo::<Bls12> {
        xl: None,
        xr: None,
        constants: &constants
    };
    c.synthesize(cs);
    log(&format!("MiMC: {}", "BLAH"))
}

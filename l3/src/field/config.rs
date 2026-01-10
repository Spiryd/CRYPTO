//! Field configuration trait
//!
//! Defines the `FieldConfig` trait used to specify field parameters
//! at compile time, enabling type-safe field arithmetic.

use crate::bigint::BigInt;

/// Configuration trait for defining finite field parameters at compile time
///
/// Types implementing this trait define the field parameters (modulus p, degree k,
/// and irreducible polynomial). The Rust type system ensures that field elements
/// with different configurations cannot be mixed.
///
/// # Type Safety
/// By using different types for different field configurations, Rust's type system
/// guarantees at compile time that operations only occur between elements of the
/// same field.
///
/// # Example
/// ```
/// use l3::bigint::BigInt;
/// use l3::field::FieldConfig;
///
/// #[derive(Clone, Debug)]
/// struct F97Config;
///
/// static F97_MODULUS: BigInt<4> = BigInt::from_u64(97);
///
/// impl FieldConfig<4> for F97Config {
///     fn modulus() -> &'static BigInt<4> {
///         &F97_MODULUS
///     }
///     
///     fn irreducible() -> &'static [BigInt<4>] {
///         &[] // Empty for prime field
///     }
/// }
/// ```
pub trait FieldConfig<const N: usize>: 'static + Sized + Clone {
    /// Returns the prime modulus p of the field
    ///
    /// This must be a static reference to ensure it's available at compile time.
    /// The modulus defines the characteristic of the field.
    ///
    /// # Returns
    /// A static reference to the prime modulus as a BigInt
    fn modulus() -> &'static BigInt<N>;

    /// Returns the irreducible polynomial coefficients (for extension fields)
    ///
    /// For F_p (prime field, k=1), return an empty slice.
    /// For F_p^k (extension field, k>1), return coefficients [a_0, a_1, ..., a_k]
    /// of the irreducible polynomial: a_0 + a_1*x + ... + a_k*x^k
    ///
    /// The polynomial must be irreducible over F_p to ensure F_p^k is a field.
    ///
    /// # Returns
    /// A static slice of BigInt coefficients
    fn irreducible() -> &'static [BigInt<N>];
}

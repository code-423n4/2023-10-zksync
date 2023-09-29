#[cfg(feature = "verbose_circuits")]
pub const CIRCUIT_VERSOBE: bool = true;

#[cfg(not(feature = "verbose_circuits"))]
pub const CIRCUIT_VERSOBE: bool = false;

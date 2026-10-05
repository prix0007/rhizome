//! Rhizome: a local, real-time 3D map of the LAN this machine is on.
//!
//! Pure logic (parsers, merge, classification) lives apart from the I/O
//! adapters so it can be unit-tested against fixtures.

pub mod config;
pub mod discovery;
pub mod enrich;
pub mod model;
pub mod net;
pub mod scanner;
pub mod state;
pub mod store;
pub mod web;

//! Refract Oracle Contract
//!
//! A permissioned price / event oracle that the RefractPool calls to verify
//! trigger conditions before processing claims. In production this would be
//! connected to Band Protocol, Pyth, or a Refract-operated relay.
//!
//! # Architecture and Invariants
//!
//! - **Fixed-Point Scaling**: All price and ratio values are represented as signed
//!   integers scaled by [`SCALE`] (1e7 precision), ensuring zero floating-point arithmetic.
//! - **Staleness Windows**: Readings must be fresher than [`MAX_STALENESS_SECS`] (1,800 seconds / 30 minutes).
//! - **Future Timestamp Defense**: Readings dated beyond the current ledger timestamp are
//!   rejected with [`OracleError::FutureTimestamp`].
//! - **Monotonic Ordering & Multi-Relayer Safety**: Because multiple relayers may submit concurrently
//!   without centralized scheduling, submissions cannot regress feed history backward in time.
//!   Any reading with a timestamp older than the stored reading for that feed is rejected with
//!   [`OracleError::StaleSubmission`].

#![no_std]
#![warn(missing_docs)]

use soroban_sdk::{
    contract, contracterror, contractimpl, contracttype, Address, Env, Map, Symbol, Vec,
};

/// Maximum oracle staleness in seconds (30 minutes).
pub const MAX_STALENESS_SECS: u64 = 1_800;

/// Fixed-point scale for value readings (1e7). All prices/percentages are
/// stored as `value * 1e7` so the contract never touches floating point.
pub const SCALE: i128 = 10_000_000;

// ── Trigger thresholds (in `SCALE` fixed-point unless noted) ────────────────
/// Trigger threshold for stablecoin depeg: USDC < $0.95 (0.95 * SCALE).
pub const DEPEG_PRICE_THRESHOLD: i128 = 95 * SCALE / 100;
/// Trigger threshold for market crash: 24h return < -30% (-0.30 * SCALE).
pub const CRASH_RETURN_THRESHOLD: i128 = -30 * SCALE / 100;
/// Trigger threshold for liquidation ratio: ratio < 85% (0.85 * SCALE).
pub const LIQUIDATION_RATIO_THRESHOLD: i128 = 85 * SCALE / 100;
/// Trigger threshold for smart contract risk TVL: TVL < $500,000.
pub const TVL_THRESHOLD: i128 = 500_000 * SCALE;
/// Trigger threshold for flight delay: duration > 120 minutes (unscaled).
pub const FLIGHT_DELAY_THRESHOLD: i128 = 120;

/// Errors returned by the oracle. `require_auth()` still panics on a
/// missing/invalid signature (unrecoverable); every other recoverable
/// misuse — wrong principal, unknown feed, stale data, double init —
/// returns a typed error instead of panicking, matching the convention
/// used by `RefractPool` and `RefractPolicyRegistry`.
#[contracterror]
#[derive(Copy, Clone, Debug, Eq, PartialEq, PartialOrd, Ord)]
#[repr(u32)]
pub enum OracleError {
    /// Contract has already been initialized.
    AlreadyInitialized = 1,
    /// Contract has not yet been initialized.
    NotInitialized = 2,
    /// Caller is not authorized to perform this operation.
    Unauthorized = 3,
    /// Requested oracle feed ID was not found.
    FeedNotFound = 4,
    /// Reading timestamp is older than the maximum staleness window.
    StaleReading = 5,
    /// Supplied coverage type is unrecognized for trigger evaluation.
    UnknownCoverageType = 6,
    /// Submitted timestamp is in the future relative to the ledger time.
    FutureTimestamp = 7,
    /// Submitted reading timestamp is older than the reading already stored for this feed.
    StaleSubmission = 8,
}

/// Oracle reading stored on-chain.
#[contracttype]
#[derive(Clone, Debug, PartialEq)]
pub struct OracleReading {
    /// Signed integer value in 1e7 precision.
    /// For prices: USD price * 1e7.
    /// For percentages: percent * 1e7 (e.g. -30% = -3_000_000).
    /// For durations: minutes.
    pub value: i128,
    /// Unix timestamp when the reading was captured.
    pub timestamp: u64,
    /// Source or provider identifier for the reading.
    pub source: Symbol,
}

/// Storage keys for oracle contract instance and persistent storage.
#[contracttype]
pub enum DataKey {
    /// Contract administrator address key (instance storage).
    Admin,
    /// List of authorized relayer addresses (instance storage).
    Relayers,
    /// Oracle reading mapped by feed symbol (persistent storage).
    Reading(Symbol),
}

/// Refract Oracle smart contract.
#[contract]
pub struct RefractOracle;

#[contractimpl]
impl RefractOracle {
    // ─── Initialization ──────────────────────────────────────────────────

    /// Initialize the oracle contract with an administrator address.
    ///
    /// Returns [`OracleError::AlreadyInitialized`] if already initialized.
    pub fn initialize(env: Env, admin: Address) -> Result<(), OracleError> {
        if env.storage().instance().has(&DataKey::Admin) {
            return Err(OracleError::AlreadyInitialized);
        }
        env.storage().instance().set(&DataKey::Admin, &admin);
        env.storage()
            .instance()
            .set(&DataKey::Relayers, &Vec::<Address>::new(&env));
        Ok(())
    }

    // ─── Admin ───────────────────────────────────────────────────────────

    /// Add an authorized relayer address allowed to submit oracle readings.
    pub fn add_relayer(env: Env, relayer: Address) -> Result<(), OracleError> {
        Self::require_admin(&env)?;
        let mut relayers: Vec<Address> = env
            .storage()
            .instance()
            .get(&DataKey::Relayers)
            .unwrap_or_else(|| Vec::new(&env));
        if !relayers.iter().any(|r| r == relayer) {
            relayers.push_back(relayer.clone());
            env.storage().instance().set(&DataKey::Relayers, &relayers);
            env.events()
                .publish((Symbol::new(&env, "relayer_added"),), (relayer,));
        }
        Ok(())
    }

    /// Remove an authorized relayer address.
    pub fn remove_relayer(env: Env, relayer: Address) -> Result<(), OracleError> {
        Self::require_admin(&env)?;
        let relayers: Vec<Address> = env
            .storage()
            .instance()
            .get(&DataKey::Relayers)
            .unwrap_or_else(|| Vec::new(&env));
        // soroban_sdk::Vec does not implement FromIterator, so rebuild manually.
        let mut filtered: Vec<Address> = Vec::new(&env);
        for r in relayers.iter() {
            if r != relayer {
                filtered.push_back(r);
            }
        }
        let removed = filtered.len() != relayers.len();
        env.storage().instance().set(&DataKey::Relayers, &filtered);
        if removed {
            env.events()
                .publish((Symbol::new(&env, "relayer_removed"),), (relayer,));
        }
        Ok(())
    }

    /// Addresses currently authorized to submit oracle readings. Before
    /// this, the only way to answer "who can relay right now" was to
    /// replay add_relayer/remove_relayer events from history.
    pub fn list_relayers(env: Env) -> Vec<Address> {
        env.storage()
            .instance()
            .get(&DataKey::Relayers)
            .unwrap_or_else(|| Vec::new(&env))
    }

    /// The address currently authorized to call
    /// add_relayer()/remove_relayer()/set_admin(). Without this, verifying
    /// who holds admin control meant replaying event history instead of
    /// just reading current state.
    pub fn admin(env: Env) -> Option<Address> {
        env.storage().instance().get(&DataKey::Admin)
    }

    /// Rotate the admin key. The only recovery path if the current admin
    /// key is lost or compromised — without it, add_relayer/remove_relayer
    /// and this function itself would be permanently stuck on whatever key
    /// was set at initialize().
    pub fn set_admin(env: Env, new_admin: Address) -> Result<(), OracleError> {
        Self::require_admin(&env)?;
        env.storage().instance().set(&DataKey::Admin, &new_admin);
        env.events()
            .publish((Symbol::new(&env, "admin_set"),), (new_admin,));
        Ok(())
    }

    // ─── Data submission ─────────────────────────────────────────────────

    /// Submit a reading for a given feed.
    /// feed_id examples: `USDC_PRICE`, `MARKET_24H_RETURN`, `XLM_TVL`, `FLIGHT_DL420`.
    ///
    /// Validates that:
    /// 1. Caller is an authorized relayer or contract admin.
    /// 2. Timestamp is not in the future relative to the ledger time.
    /// 3. Reading is not older than [`MAX_STALENESS_SECS`].
    /// 4. Timestamp is greater than or equal to any currently stored reading for this feed.
    pub fn submit(
        env: Env,
        relayer: Address,
        feed_id: Symbol,
        value: i128,
        timestamp: u64,
        source: Symbol,
    ) -> Result<(), OracleError> {
        relayer.require_auth();
        Self::require_relayer(&env, &relayer)?;

        let ledger_time = env.ledger().timestamp();

        // saturating_sub means a future-dated timestamp would otherwise
        // compute age=0 and sail through the staleness check below as if
        // it were perfectly fresh — and, once stored, get_reading()'s own
        // staleness check has the same blind spot, so a bad reading like
        // this wouldn't naturally expire until real time caught up to it.
        // Reject it outright instead.
        if timestamp > ledger_time {
            return Err(OracleError::FutureTimestamp);
        }

        // Reject readings older than MAX_STALENESS_SECS
        let age = ledger_time - timestamp;
        if age > MAX_STALENESS_SECS {
            return Err(OracleError::StaleReading);
        }

        // Multiple relayers can be registered at once (add_relayer supports
        // a list), and nothing orders their submissions relative to each
        // other. Without this check, a submission that's individually
        // "fresh enough" (within MAX_STALENESS_SECS of now) could still be
        // older than the reading already on file — e.g. two relayers racing,
        // or one submitting out of order — silently regressing the feed
        // backward in time and potentially un-triggering (or reviving) a
        // claim based on stale data replacing a more current reading.
        if let Some(existing) = env
            .storage()
            .persistent()
            .get::<DataKey, OracleReading>(&DataKey::Reading(feed_id.clone()))
        {
            if timestamp < existing.timestamp {
                return Err(OracleError::StaleSubmission);
            }
        }

        let reading = OracleReading {
            value,
            timestamp,
            source,
        };
        env.storage()
            .persistent()
            .set(&DataKey::Reading(feed_id.clone()), &reading);

        env.events().publish(
            (Symbol::new(&env, "oracle_updated"), feed_id),
            (value, timestamp),
        );
        Ok(())
    }

    // ─── Queries ─────────────────────────────────────────────────────────

    /// Get the latest reading for a feed. Errors if not found or stale.
    pub fn get_reading(env: Env, feed_id: Symbol) -> Result<OracleReading, OracleError> {
        let reading: OracleReading = env
            .storage()
            .persistent()
            .get(&DataKey::Reading(feed_id))
            .ok_or(OracleError::FeedNotFound)?;

        let ledger_time = env.ledger().timestamp();
        let age = ledger_time.saturating_sub(reading.timestamp);
        if age > MAX_STALENESS_SECS {
            return Err(OracleError::StaleReading);
        }

        Ok(reading)
    }

    /// Returns true if the trigger condition for a given coverage type is met.
    /// coverage_type: 0=Depeg, 1=Crash, 2=Liquidation, 3=SmartContract, 4=Flight.
    pub fn is_triggered(
        env: Env,
        coverage_type: u32,
        feed_id: Symbol,
    ) -> Result<bool, OracleError> {
        let reading = Self::get_reading(env, feed_id)?;

        match coverage_type {
            0 => Ok(reading.value < DEPEG_PRICE_THRESHOLD),
            1 => Ok(reading.value < CRASH_RETURN_THRESHOLD),
            2 => Ok(reading.value < LIQUIDATION_RATIO_THRESHOLD),
            3 => Ok(reading.value < TVL_THRESHOLD),
            4 => Ok(reading.value > FLIGHT_DELAY_THRESHOLD),
            _ => Err(OracleError::UnknownCoverageType),
        }
    }

    /// Get all feeds and their timestamps as a map (for monitoring UI).
    pub fn list_feeds(env: Env, feed_ids: Vec<Symbol>) -> Map<Symbol, i64> {
        let mut out: Map<Symbol, i64> = Map::new(&env);
        for feed_id in feed_ids.iter() {
            if let Some(r) = env
                .storage()
                .persistent()
                .get::<DataKey, OracleReading>(&DataKey::Reading(feed_id.clone()))
            {
                out.set(feed_id, r.timestamp as i64);
            }
        }
        out
    }

    // ─── Internal helpers ─────────────────────────────────────────────────

    fn require_admin(env: &Env) -> Result<(), OracleError> {
        let admin: Address = env
            .storage()
            .instance()
            .get(&DataKey::Admin)
            .ok_or(OracleError::NotInitialized)?;
        admin.require_auth();
        Ok(())
    }

    fn require_relayer(env: &Env, caller: &Address) -> Result<(), OracleError> {
        let relayers: Vec<Address> = env
            .storage()
            .instance()
            .get(&DataKey::Relayers)
            .unwrap_or_else(|| Vec::new(env));
        let is_relayer = relayers.iter().any(|r| &r == caller);
        // Admin can also submit
        let admin: Address = env
            .storage()
            .instance()
            .get(&DataKey::Admin)
            .ok_or(OracleError::NotInitialized)?;
        if !is_relayer && caller != &admin {
            return Err(OracleError::Unauthorized);
        }
        Ok(())
    }
}

#[cfg(test)]
mod test;

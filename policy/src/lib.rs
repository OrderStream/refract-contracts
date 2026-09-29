//! Refract Policy Registry Contract
//!
//! Stores all policy metadata on-chain as a lightweight sidecar to the Pool
//! contract. The Pool contract is the source of truth for capital; this
//! contract provides a queryable index of policies per holder.
//!
//! # Architecture and Invariants
//!
//! - **Source of Truth**: The Pool contract is the source of truth for capital and
//!   policy IDs. The registry does not mint IDs independently; it mirrors the IDs
//!   allocated by the Pool contract so both contracts stay in lockstep.
//! - **Access Control**: Only the authorized Pool contract or the admin may register
//!   or deactivate policies via [`register_policy`](RefractPolicyRegistry::register_policy)
//!   and [`deactivate_policy`](RefractPolicyRegistry::deactivate_policy).
//! - **Idempotent Deactivation**: Deactivating an already inactive policy is a safe no-op,
//!   preventing event spam and underflow of active policy counters.
//! - **Cross-contract Type Parity**: [`CoverageType`] matches the enum layout of
//!   `RegistryCoverageType` in the pool contract crate.

#![no_std]
#![warn(missing_docs)]

use soroban_sdk::{
    contract, contracterror, contractimpl, contracttype, Address, Env, Map, Symbol, Vec,
};

/// Coverage types offered across the protocol (must match RefractPool enum).
#[contracttype]
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
#[repr(u32)]
pub enum CoverageType {
    /// Coverage against stablecoin peg deviation (e.g. USDC < $0.95).
    StablecoinDepeg = 0,
    /// Coverage against broad market drawdowns (e.g. 24h return < -30%).
    MarketCrash = 1,
    /// Protection against DeFi collateral liquidation events.
    LiquidationShield = 2,
    /// Coverage against smart contract exploits or protocol TVL collapse.
    SmartContractRisk = 3,
    /// Parametric flight delay coverage (> 120 minutes).
    FlightDelay = 4,
}

/// Errors returned by the registry. State-changing entrypoints still call
/// `require_auth()` directly (which panics on a missing/invalid signature —
/// that failure mode is not recoverable), but every *recoverable* misuse
/// (wrong principal, unknown policy, double init) returns a typed error
/// instead of panicking, matching the convention used by `RefractPool`.
#[contracterror]
#[derive(Copy, Clone, Debug, Eq, PartialEq, PartialOrd, Ord)]
#[repr(u32)]
pub enum RegistryError {
    /// Contract has already been initialized.
    AlreadyInitialized = 1,
    /// Contract has not yet been initialized.
    NotInitialized = 2,
    /// Caller is not authorized to perform the requested operation.
    Unauthorized = 3,
    /// Requested policy ID was not found in storage.
    PolicyNotFound = 4,
    /// A policy with the specified ID already exists in storage.
    PolicyAlreadyExists = 5,
}

/// Parameters for indexing a policy that the Pool contract already created.
/// Grouped into a struct (rather than passed as loose arguments) to stay
/// under clippy's argument-count lint and to give the pool↔registry wiring a
/// single, easy-to-extend payload type.
#[contracttype]
#[derive(Clone, Debug)]
pub struct PolicyRegistration {
    /// Unique policy ID assigned by the Pool contract.
    pub policy_id: u64,
    /// Address of the policyholder.
    pub holder: Address,
    /// Type of insurance coverage.
    pub coverage_type: CoverageType,
    /// Covered payout amount in 1e7 USDC units.
    pub coverage_amount: i128,
    /// Upfront premium paid in 1e7 USDC units.
    pub premium: i128,
    /// Unix timestamp when coverage expires.
    pub expires_at: u64,
}

/// On-chain policy record stored in contract persistent storage.
#[contracttype]
#[derive(Clone, Debug, PartialEq)]
pub struct PolicyRecord {
    /// Unique policy ID assigned by the Pool contract.
    pub policy_id: u64,
    /// Address of the policyholder.
    pub holder: Address,
    /// Type of insurance coverage.
    pub coverage_type: CoverageType,
    /// Covered payout amount in 1e7 USDC units.
    pub coverage_amount: i128,
    /// Upfront premium paid in 1e7 USDC units.
    pub premium: i128,
    /// Unix timestamp when coverage expires.
    pub expires_at: u64,
    /// Whether the policy is currently active.
    pub is_active: bool,
    /// Unix timestamp when the policy was registered.
    pub created_at: u64,
}

/// Storage keys for contract instance and persistent storage.
#[contracttype]
pub enum DataKey {
    /// Admin address key (instance storage).
    Admin,
    /// Authorized Pool contract address key (instance storage).
    PoolContract,
    /// Policy record mapped by policy ID (persistent storage).
    Policy(u64),
    /// List of policy IDs mapped by holder address (persistent storage).
    HolderPolicies(Address),
    /// Cumulative count of registered policies (instance storage).
    TotalPolicies,
    /// Cumulative volume of collected premiums in 1e7 USDC (instance storage).
    TotalPremium,
    /// Count of currently active policies (instance storage).
    ActivePolicies,
}

/// Refract Policy Registry smart contract.
#[contract]
pub struct RefractPolicyRegistry;

#[contractimpl]
impl RefractPolicyRegistry {
    // ─── Initialization ───────────────────────────────────────────────────

    /// Initialize the policy registry contract with an admin and pool contract address.
    ///
    /// Returns [`RegistryError::AlreadyInitialized`] if already initialized.
    pub fn initialize(
        env: Env,
        admin: Address,
        pool_contract: Address,
    ) -> Result<(), RegistryError> {
        if env.storage().instance().has(&DataKey::Admin) {
            return Err(RegistryError::AlreadyInitialized);
        }
        env.storage().instance().set(&DataKey::Admin, &admin);
        env.storage()
            .instance()
            .set(&DataKey::PoolContract, &pool_contract);
        env.storage().instance().set(&DataKey::TotalPolicies, &0u64);
        env.storage().instance().set(&DataKey::TotalPremium, &0i128);
        env.storage()
            .instance()
            .set(&DataKey::ActivePolicies, &0u64);
        Ok(())
    }

    // ─── Policy registration (called by Pool contract) ───────────────────

    /// Index a policy that was already created (and id-assigned) by the Pool
    /// contract. The Pool is the source of truth for policy ids — the
    /// registry does not mint its own, it just mirrors the id the pool
    /// picked so the two stay in lockstep and a policy can be looked up by
    /// the same id in either contract.
    pub fn register_policy(
        env: Env,
        caller: Address,
        reg: PolicyRegistration,
    ) -> Result<u64, RegistryError> {
        Self::require_pool_or_admin(&env, &caller)?;

        let PolicyRegistration {
            policy_id,
            holder,
            coverage_type,
            coverage_amount,
            premium,
            expires_at,
        } = reg;

        if env.storage().persistent().has(&DataKey::Policy(policy_id)) {
            return Err(RegistryError::PolicyAlreadyExists);
        }

        let record = PolicyRecord {
            policy_id,
            holder: holder.clone(),
            coverage_type,
            coverage_amount,
            premium,
            expires_at,
            is_active: true,
            created_at: env.ledger().timestamp(),
        };

        env.storage()
            .persistent()
            .set(&DataKey::Policy(policy_id), &record);

        // Append to holder index
        let mut holder_policies: Vec<u64> = env
            .storage()
            .persistent()
            .get(&DataKey::HolderPolicies(holder.clone()))
            .unwrap_or_else(|| Vec::new(&env));
        holder_policies.push_back(policy_id);
        env.storage()
            .persistent()
            .set(&DataKey::HolderPolicies(holder), &holder_policies);

        // Update counters
        let total: u64 = env
            .storage()
            .instance()
            .get(&DataKey::TotalPolicies)
            .unwrap_or(0);
        env.storage()
            .instance()
            .set(&DataKey::TotalPolicies, &(total + 1));
        let total_premium: i128 = env
            .storage()
            .instance()
            .get(&DataKey::TotalPremium)
            .unwrap_or(0);
        env.storage()
            .instance()
            .set(&DataKey::TotalPremium, &(total_premium + premium));
        let active: u64 = env
            .storage()
            .instance()
            .get(&DataKey::ActivePolicies)
            .unwrap_or(0);
        env.storage()
            .instance()
            .set(&DataKey::ActivePolicies, &(active + 1));

        env.events().publish(
            (Symbol::new(&env, "policy_registered"), policy_id),
            (coverage_type as u32, coverage_amount),
        );

        Ok(policy_id)
    }

    /// Deactivate an active policy upon claim settlement or expiration.
    ///
    /// If the policy is already inactive, this is a no-op to prevent duplicate event
    /// emission or underflow of active policy counters.
    pub fn deactivate_policy(
        env: Env,
        caller: Address,
        policy_id: u64,
    ) -> Result<(), RegistryError> {
        Self::require_pool_or_admin(&env, &caller)?;
        let mut record: PolicyRecord = env
            .storage()
            .persistent()
            .get(&DataKey::Policy(policy_id))
            .ok_or(RegistryError::PolicyNotFound)?;

        // Was already inactive — a no-op. Without this guard, calling
        // deactivate_policy twice on the same policy_id would double-emit
        // policy_deactivated and (since ActivePolicies was added) double-
        // decrement the active count below zero.
        if !record.is_active {
            return Ok(());
        }

        record.is_active = false;
        env.storage()
            .persistent()
            .set(&DataKey::Policy(policy_id), &record);

        let active: u64 = env
            .storage()
            .instance()
            .get(&DataKey::ActivePolicies)
            .unwrap_or(0);
        env.storage()
            .instance()
            .set(&DataKey::ActivePolicies, &active.saturating_sub(1));

        env.events()
            .publish((Symbol::new(&env, "policy_deactivated"), policy_id), ());
        Ok(())
    }

    // ─── Admin ────────────────────────────────────────────────────────────

    /// Repoint the RefractPool this registry trusts to call
    /// `register_policy()`/`deactivate_policy()`. Only needed after a pool
    /// redeploy/migration — `initialize` already wires the pool address
    /// set at deploy time. Deliberately admin-only rather than
    /// admin-or-pool (unlike register_policy/deactivate_policy): the pool
    /// itself must never be able to redirect which pool address the
    /// registry trusts.
    pub fn set_pool_contract(
        env: Env,
        caller: Address,
        pool_contract: Address,
    ) -> Result<(), RegistryError> {
        Self::require_admin(&env, &caller)?;
        env.storage()
            .instance()
            .set(&DataKey::PoolContract, &pool_contract);

        env.events()
            .publish((Symbol::new(&env, "pool_contract_set"),), (pool_contract,));
        Ok(())
    }

    /// Rotate the admin key. The only recovery path if the current admin
    /// key is lost or compromised — without it, set_pool_contract and this
    /// function itself would be permanently stuck on whatever key was set
    /// at initialize().
    pub fn set_admin(env: Env, caller: Address, new_admin: Address) -> Result<(), RegistryError> {
        Self::require_admin(&env, &caller)?;
        env.storage().instance().set(&DataKey::Admin, &new_admin);

        env.events()
            .publish((Symbol::new(&env, "admin_set"),), (new_admin,));
        Ok(())
    }

    // ─── Queries ──────────────────────────────────────────────────────────

    /// Retrieve the [`PolicyRecord`] for a given policy ID.
    pub fn get_policy(env: Env, policy_id: u64) -> Result<PolicyRecord, RegistryError> {
        env.storage()
            .persistent()
            .get(&DataKey::Policy(policy_id))
            .ok_or(RegistryError::PolicyNotFound)
    }

    /// Retrieve all policy IDs associated with a given holder address.
    pub fn get_holder_policy_ids(env: Env, holder: Address) -> Vec<u64> {
        env.storage()
            .persistent()
            .get(&DataKey::HolderPolicies(holder))
            .unwrap_or_else(|| Vec::new(&env))
    }

    /// Same as get_holder_policy_ids, filtered to currently-active policies.
    /// Without this, a caller wanting "what does this holder have active
    /// right now" had to fetch every id the holder has ever had and call
    /// get_policy on each one just to check is_active.
    pub fn get_holder_active_policy_ids(env: Env, holder: Address) -> Vec<u64> {
        let ids: Vec<u64> = env
            .storage()
            .persistent()
            .get(&DataKey::HolderPolicies(holder))
            .unwrap_or_else(|| Vec::new(&env));

        let mut active = Vec::new(&env);
        for id in ids.iter() {
            if let Some(record) = env
                .storage()
                .persistent()
                .get::<DataKey, PolicyRecord>(&DataKey::Policy(id))
            {
                if record.is_active {
                    active.push_back(id);
                }
            }
        }
        active
    }

    /// Retrieve aggregate registry statistics (total policies, total premium volume, active count).
    pub fn get_stats(env: Env) -> Map<Symbol, i128> {
        let mut stats: Map<Symbol, i128> = Map::new(&env);
        let total: u64 = env
            .storage()
            .instance()
            .get(&DataKey::TotalPolicies)
            .unwrap_or(0);
        let premium: i128 = env
            .storage()
            .instance()
            .get(&DataKey::TotalPremium)
            .unwrap_or(0);
        let active: u64 = env
            .storage()
            .instance()
            .get(&DataKey::ActivePolicies)
            .unwrap_or(0);
        stats.set(Symbol::new(&env, "total_policies"), total as i128);
        stats.set(Symbol::new(&env, "total_premium"), premium);
        stats.set(Symbol::new(&env, "active_policies"), active as i128);
        stats
    }

    /// The address currently authorized to call set_admin()/
    /// set_pool_contract(). Without this, verifying who holds admin
    /// control meant replaying event history instead of just reading
    /// current state.
    pub fn admin(env: Env) -> Option<Address> {
        env.storage().instance().get(&DataKey::Admin)
    }

    /// The RefractPool address this registry currently trusts to call
    /// register_policy()/deactivate_policy(). Without this,
    /// set_pool_contract() would be a write with no matching read.
    pub fn pool_contract(env: Env) -> Option<Address> {
        env.storage().instance().get(&DataKey::PoolContract)
    }

    // ─── Internal ─────────────────────────────────────────────────────────

    /// Only the registered Pool contract or the admin may mutate the registry.
    /// The caller must authorize the invocation (this panics on a missing or
    /// invalid signature — not recoverable); we then verify the authorized
    /// address is one of the two privileged principals, which *is* recoverable
    /// and reported as a typed error.
    fn require_pool_or_admin(env: &Env, caller: &Address) -> Result<(), RegistryError> {
        caller.require_auth();
        let admin: Address = env
            .storage()
            .instance()
            .get(&DataKey::Admin)
            .ok_or(RegistryError::NotInitialized)?;
        let pool: Address = env
            .storage()
            .instance()
            .get(&DataKey::PoolContract)
            .ok_or(RegistryError::NotInitialized)?;
        if caller != &admin && caller != &pool {
            return Err(RegistryError::Unauthorized);
        }
        Ok(())
    }

    /// Stricter than require_pool_or_admin: used by set_pool_contract and
    /// set_admin, which must never be callable by the pool contract itself.
    fn require_admin(env: &Env, caller: &Address) -> Result<(), RegistryError> {
        caller.require_auth();
        let admin: Address = env
            .storage()
            .instance()
            .get(&DataKey::Admin)
            .ok_or(RegistryError::NotInitialized)?;
        if caller != &admin {
            return Err(RegistryError::Unauthorized);
        }
        Ok(())
    }
}

#[cfg(test)]
mod test;

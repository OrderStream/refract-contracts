//! Refract Risk Pool Contract
//!
//! The central risk-bearing, capital-management, and underwriting contract for
//! Refract Protocol. Liquidity providers deposit USDC to underwrite parametric
//! insurance policies across predefined risk categories (stablecoin depegs,
//! market crashes, liquidation events, smart contract exploits, and flight delays).
//!
//! # Architecture & Cross-Contract Interactions
//!
//! The Refract Protocol operates across three specialized contracts:
//!
//! - **RefractPool (this contract)**: The ultimate source of truth for capital,
//!   shares, policy pricing, and claim payouts.
//! - **RefractPolicyRegistry**: A lightweight index of historical and active
//!   policies grouped per policyholder for frontend and indexing queries.
//! - **RefractOracle**: An authenticated multi-relayer oracle providing fresh
//!   metric readings to verify claim triggers.
//!
//! # Key Architectural Invariants
//!
//! 1. **ABI-Mirroring Rationale (`RegistryCoverageType` and `PolicyRegistration`)**:
//!    The pool calls into `RefractPolicyRegistry` via `env.invoke_contract` rather
//!    than taking a source-level dependency on the `refract-policy` crate.
//!    Because Soroban's `#[contractimpl]` exports symbol names for `wasm32` compiles
//!    regardless of crate type, a source dependency causes duplicate export collisions
//!    at wasm link time (e.g., both contracts defining `get_policy`). Locally
//!    mirroring argument and return types keeps each wasm artifact self-contained
//!    while remaining wire-compatible under Soroban XDR serialization.
//!
//! 2. **Best-Effort Registry Deactivation (`_deactivate_in_registry`)**:
//!    When a policy claim is paid out or expired, the pool notifies the registry to
//!    deactivate the mirrored record. This cross-contract call is strictly best-effort
//!    and non-blocking using `env.try_invoke_contract`. The pool's own internal
//!    state is always authoritative; funds transferred to a legitimate policyholder
//!    must never be rolled back if the secondary registry index reverts or fails.
//!
//! 3. **Withdrawal Protection & Utilization Bound (`_quote_withdrawal`)**:
//!    No liquidity provider can redeem more shares than exist in `TotalShares`.
//!    Redemptions are gated so that post-withdrawal capital keeps pool utilization
//!    below `max_utilization_bps`, preventing capital lockups during active risk periods.
//!
//! 4. **No Value Created from Thin Air (`_calc_shares`)**:
//!    Share minting and redemption follow `shares = amount * TotalShares / TotalCapital`.
//!    Integer truncation guarantees that newly minted shares can never dilute
//!    existing liquidity providers or mint unbacked claims.

#![no_std]
#![warn(missing_docs)]

use soroban_sdk::{
    contract, contracterror, contractimpl, contracttype, symbol_short, token, Address, Env,
    IntoVal, Symbol, Vec,
};

const PRECISION: i128 = 10_000_000i128;
const BPS: i128 = 10_000i128;

// ── Coverage categories ───────────────────────────────────────────────────────

/// Supported parametric insurance coverage categories underwritten by the pool.
#[contracttype]
#[derive(Clone, Debug, PartialEq)]
pub enum CoverageType {
    /// Stablecoin depeg coverage (e.g. USDC price drops below peg threshold).
    StablecoinDepeg,
    /// Broad crypto market crash protection (e.g. XLM/BTC drops >30% in 24h).
    MarketCrash,
    /// Liquidation shield protecting borrow positions on integrated lending markets.
    LiquidationShield,
    /// Smart contract risk protection against protocol exploits or hacks.
    SmartContractRisk,
    /// Parametric flight delay insurance based on airline schedule feeds.
    FlightDelay,
}

// ── RefractPolicyRegistry ABI mirror ────────────────────────────────────────

/// Wire-compatible mirror of the Policy Registry's coverage type enum.
///
/// Mirrors the registry's definition field-for-field to prevent wasm link-time
/// symbol collisions while ensuring identical XDR serialization.
#[contracttype]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u32)]
pub enum RegistryCoverageType {
    /// Mirror of `CoverageType::StablecoinDepeg`.
    StablecoinDepeg = 0,
    /// Mirror of `CoverageType::MarketCrash`.
    MarketCrash = 1,
    /// Mirror of `CoverageType::LiquidationShield`.
    LiquidationShield = 2,
    /// Mirror of `CoverageType::SmartContractRisk`.
    SmartContractRisk = 3,
    /// Mirror of `CoverageType::FlightDelay`.
    FlightDelay = 4,
}

/// Payload sent to `RefractPolicyRegistry::register_policy`.
///
/// Mirrors the policy registry's struct definition field-for-field.
#[contracttype]
#[derive(Clone, Debug)]
pub struct PolicyRegistration {
    /// Unique policy identifier assigned by RefractPool.
    pub policy_id: u64,
    /// Address of the policyholder.
    pub holder: Address,
    /// Coverage category on the registry wire.
    pub coverage_type: RegistryCoverageType,
    /// Maximum payout amount in 1e7 USDC units.
    pub coverage_amount: i128,
    /// Total upfront premium charged in 1e7 USDC units.
    pub premium: i128,
    /// Expiration timestamp in seconds since Unix epoch.
    pub expires_at: u64,
}

// ── Storage Keys ──────────────────────────────────────────────────────────────

/// Storage keys for contract instance and persistent state entries.
#[contracttype]
#[derive(Clone)]
pub enum DataKey {
    /// Protocol administrator address authorized for operational parameters.
    Admin,
    /// Underlying USDC asset token address.
    UsdcToken,
    /// External `RefractPolicyRegistry` contract address for secondary indexing.
    PolicyRegistry,
    /// Total capital held in the pool in 1e7 USDC units.
    TotalCapital,
    /// Sum of all active policy coverage amounts currently underwritten.
    TotalCoverage,
    /// Cumulative premiums earned across all historical policy purchases.
    TotalPremiums,
    /// Pool LP share balance mapped per provider address.
    Shares(Address),
    /// Total outstanding LP pool shares minted.
    TotalShares,
    /// Stored policy record mapped by unique policy ID.
    Policy(u64),
    /// List of policy IDs owned by a specific policyholder address.
    UserPolicies(Address),
    /// Auto-incrementing policy ID counter for new policies.
    NextPolicyId,
    /// Operational configuration parameters (rates, caps, lockup period).
    PoolConfig,
    /// Boolean flag indicating whether contract has been initialized.
    Initialized,
    /// Latest verified oracle reading cached per coverage type.
    OracleData(CoverageType),
    /// Timestamp of a liquidity provider's most recent deposit.
    LastDeposit(Address),
}

// ── Errors ────────────────────────────────────────────────────────────────────

/// Error codes returned by entrypoints of the `RefractPool` contract.
#[contracterror]
#[derive(Copy, Clone, Debug, Eq, PartialEq, PartialOrd, Ord)]
#[repr(u32)]
pub enum PoolError {
    /// The pool contract is already initialized.
    AlreadyInitialized = 1,
    /// The pool contract has not been initialized yet.
    NotInitialized = 2,
    /// Caller is not authorized to invoke this administrative function.
    Unauthorized = 3,
    /// Underwriting capacity exceeded or requested coverage outside configured limits.
    InsufficientCapacity = 4,
    /// Requested policy ID was not found in storage.
    PolicyNotFound = 5,
    /// The policy duration has lapsed and the policy is expired.
    PolicyExpired = 6,
    /// The oracle data does not satisfy the policy trigger conditions.
    PolicyNotTriggered = 7,
    /// The caller is not the owner of the specified policy.
    NotPolicyholder = 8,
    /// The policy has already been claimed or paid out.
    AlreadyClaimed = 9,
    /// Provided premium payment is insufficient for the requested coverage.
    InsufficientPremium = 10,
    /// Amount must be greater than zero.
    ZeroAmount = 11,
    /// Provider does not hold enough shares to complete the withdrawal.
    InsufficientShares = 12,
    /// Withdrawal rejected because post-withdrawal utilization exceeds maximum capacity.
    CapitalLocked = 13,
    /// Policy cannot be expired because its coverage duration has not ended yet.
    PolicyNotYetExpired = 14,
    /// Withdrawal locked because mandatory LP lockup duration has not elapsed since deposit.
    LockupActive = 15,
}

// ── Types ─────────────────────────────────────────────────────────────────────

/// Input parameters for quoting and purchasing an insurance policy.
#[contracttype]
#[derive(Clone, Debug)]
pub struct PolicyParams {
    /// Desired coverage payout amount in 1e7 USDC units.
    pub coverage_amount: i128,
    /// Category of parametric risk to insure.
    pub coverage_type: CoverageType,
    /// Policy duration in days.
    pub duration_days: u32,
    /// Metric threshold required to trigger payout (e.g. 500 = 5% for depeg).
    pub trigger_threshold: i128,
}

/// Lifecycle status of an underwritten insurance policy.
#[contracttype]
#[derive(Clone, Debug, PartialEq)]
pub enum PolicyStatus {
    /// Policy is active and within its valid coverage duration.
    Active,
    /// Payout was approved and settled to the policyholder.
    Claimed,
    /// Coverage period ended without a triggering claim event.
    Expired,
}

/// Complete on-chain policy record stored in persistent storage.
#[contracttype]
#[derive(Clone, Debug)]
pub struct Policy {
    /// Unique policy identification number.
    pub id: u64,
    /// Address of the insured policyholder.
    pub holder: Address,
    /// Insured risk category.
    pub coverage_type: CoverageType,
    /// Payout amount owed upon valid claim trigger.
    pub coverage_amount: i128,
    /// Upfront premium paid by the holder in 1e7 USDC units.
    pub premium_paid: i128,
    /// Metric trigger threshold set at purchase.
    pub trigger_threshold: i128,
    /// Unix timestamp when policy coverage became active.
    pub start_time: u64,
    /// Unix timestamp when policy coverage lapses.
    pub end_time: u64,
    /// Current lifecycle status of the policy.
    pub status: PolicyStatus,
    /// Unix timestamp of claim settlement, if claimed.
    pub payout_at: Option<u64>,
}

/// Operational parameters controlling rates, underwriting bounds, and risk limits.
#[contracttype]
#[derive(Clone, Debug, PartialEq)]
pub struct PoolConfig {
    /// Annual base premium rate in basis points (e.g. 300 = 3% APR).
    pub base_premium_rate_bps: u32,
    /// Maximum allowed utilization of capital in basis points (e.g. 8000 = 80%).
    pub max_utilization_bps: u32,
    /// Minimum allowed single policy coverage amount in 1e7 USDC units.
    pub min_coverage: i128,
    /// Maximum allowed single policy coverage amount in 1e7 USDC units.
    pub max_coverage: i128,
    /// Liquidity provider deposit lockup period in days.
    pub lockup_days: u32,
}

/// Aggregate metrics and utilization statistics describing current pool health.
#[contracttype]
#[derive(Clone, Debug)]
pub struct PoolStats {
    /// Total underwriting capital currently deposited in the pool.
    pub total_capital: i128,
    /// Sum of all active policy coverage liabilities currently outstanding.
    pub total_coverage: i128,
    /// Total pool LP shares currently in circulation.
    pub total_shares: i128,
    /// Current utilization ratio in basis points (coverage / capital).
    pub utilization_bps: u32,
    /// Value of one full pool share in 1e7 USDC precision.
    pub share_price: i128,
    /// Estimated annual percentage yield in basis points.
    pub apy_estimate_bps: u32,
    /// Remaining coverage amount that can be underwritten before reaching utilization cap.
    pub available_capacity: i128,
}

/// Cached oracle metric reading for claim trigger verification.
#[contracttype]
#[derive(Clone, Debug)]
pub struct OracleData {
    /// Verified metric reading value in 1e7 precision scale.
    pub value: i128,
    /// Unix timestamp when this reading was updated.
    pub updated_at: u64,
}

// ── Contract ──────────────────────────────────────────────────────────────────

/// The main Refract insurance risk pool contract.
#[contract]
pub struct RefractPool;

#[contractimpl]
impl RefractPool {
    /// Initialize the RefractPool contract with administrative and token addresses.
    ///
    /// Can only be called once. Sets default risk parameters: 3% base rate,
    /// 80% maximum utilization cap, 10 USDC min coverage, 5000 USDC max coverage,
    /// and a 7-day LP lockup period.
    pub fn initialize(
        env: Env,
        admin: Address,
        usdc_token: Address,
        policy_registry: Address,
    ) -> Result<(), PoolError> {
        if env.storage().instance().has(&DataKey::Initialized) {
            return Err(PoolError::AlreadyInitialized);
        }
        admin.require_auth();

        env.storage().instance().set(&DataKey::Admin, &admin);
        env.storage()
            .instance()
            .set(&DataKey::UsdcToken, &usdc_token);
        env.storage()
            .instance()
            .set(&DataKey::PolicyRegistry, &policy_registry);
        env.storage().instance().set(&DataKey::TotalCapital, &0i128);
        env.storage()
            .instance()
            .set(&DataKey::TotalCoverage, &0i128);
        env.storage()
            .instance()
            .set(&DataKey::TotalPremiums, &0i128);
        env.storage().instance().set(&DataKey::TotalShares, &0i128);
        env.storage().instance().set(&DataKey::NextPolicyId, &0u64);

        let config = PoolConfig {
            base_premium_rate_bps: 300,       // 3% base
            max_utilization_bps: 8_000,       // 80% max
            min_coverage: 100_000_000i128,    // 10 USDC
            max_coverage: 50_000_000_000i128, // 5,000 USDC
            lockup_days: 7,
        };
        env.storage().instance().set(&DataKey::PoolConfig, &config);
        env.storage().instance().set(&DataKey::Initialized, &true);

        env.events().publish((symbol_short!("INIT"),), (admin,));
        Ok(())
    }

    // ── Capital Provision ─────────────────────────────────────────────────────

    /// Preview the LP shares a deposit of `amount` would mint without executing it.
    ///
    /// Allows potential providers to preview the exchange rate before depositing funds.
    pub fn quote_shares(env: Env, amount: i128) -> Result<i128, PoolError> {
        Self::assert_initialized(&env)?;
        if amount <= 0 {
            return Err(PoolError::ZeroAmount);
        }
        Ok(Self::_calc_shares(&env, amount))
    }

    /// Deposit USDC as risk capital into the pool and receive newly minted pool shares.
    ///
    /// Requires authorization from `provider`. Resets the LP's lockup countdown.
    pub fn provide_capital(env: Env, provider: Address, amount: i128) -> Result<i128, PoolError> {
        provider.require_auth();
        Self::assert_initialized(&env)?;
        if amount <= 0 {
            return Err(PoolError::ZeroAmount);
        }

        let usdc: Address = env.storage().instance().get(&DataKey::UsdcToken).unwrap();
        token::Client::new(&env, &usdc).transfer(
            &provider,
            &env.current_contract_address(),
            &amount,
        );

        let shares = Self::_calc_shares(&env, amount);

        let mut total_capital: i128 = env
            .storage()
            .instance()
            .get(&DataKey::TotalCapital)
            .unwrap_or(0);
        let mut total_shares: i128 = env
            .storage()
            .instance()
            .get(&DataKey::TotalShares)
            .unwrap_or(0);
        let mut user_shares: i128 = env
            .storage()
            .persistent()
            .get(&DataKey::Shares(provider.clone()))
            .unwrap_or(0);

        total_capital += amount;
        total_shares += shares;
        user_shares += shares;

        env.storage()
            .instance()
            .set(&DataKey::TotalCapital, &total_capital);
        env.storage()
            .instance()
            .set(&DataKey::TotalShares, &total_shares);
        env.storage()
            .persistent()
            .set(&DataKey::Shares(provider.clone()), &user_shares);

        env.storage().persistent().set(
            &DataKey::LastDeposit(provider.clone()),
            &env.ledger().timestamp(),
        );

        env.events()
            .publish((symbol_short!("PROVIDE"), provider), (amount, shares));
        Ok(shares)
    }

    /// Preview the USDC amount a withdrawal of `shares` would return right now.
    ///
    /// Verifies that post-withdrawal capital does not breach the pool's utilization limit.
    pub fn quote_withdrawal(env: Env, shares: i128) -> Result<i128, PoolError> {
        Self::assert_initialized(&env)?;
        if shares <= 0 {
            return Err(PoolError::ZeroAmount);
        }
        Self::_quote_withdrawal(&env, shares)
    }

    /// Withdraw capital from the pool by burning LP shares.
    ///
    /// Requires authorization from `provider`. Enforces that the mandatory `lockup_days`
    /// have passed since the provider's last deposit and that remaining pool utilization
    /// remains within safety limits.
    pub fn withdraw_capital(env: Env, provider: Address, shares: i128) -> Result<i128, PoolError> {
        provider.require_auth();
        Self::assert_initialized(&env)?;
        if shares <= 0 {
            return Err(PoolError::ZeroAmount);
        }

        let user_shares: i128 = env
            .storage()
            .persistent()
            .get(&DataKey::Shares(provider.clone()))
            .unwrap_or(0);
        if user_shares < shares {
            return Err(PoolError::InsufficientShares);
        }

        let config: PoolConfig = env.storage().instance().get(&DataKey::PoolConfig).unwrap();
        let last_deposit: Option<u64> = env
            .storage()
            .persistent()
            .get(&DataKey::LastDeposit(provider.clone()));
        if let Some(last_deposit) = last_deposit {
            let unlocks_at = last_deposit + (config.lockup_days as u64) * 86_400;
            if env.ledger().timestamp() < unlocks_at {
                return Err(PoolError::LockupActive);
            }
        }

        let usdc_out = Self::_quote_withdrawal(&env, shares)?;
        let total_capital: i128 = env
            .storage()
            .instance()
            .get(&DataKey::TotalCapital)
            .unwrap_or(0);
        let total_shares: i128 = env
            .storage()
            .instance()
            .get(&DataKey::TotalShares)
            .unwrap_or(0);

        env.storage()
            .instance()
            .set(&DataKey::TotalCapital, &(total_capital - usdc_out));
        env.storage()
            .instance()
            .set(&DataKey::TotalShares, &(total_shares - shares));
        env.storage()
            .persistent()
            .set(&DataKey::Shares(provider.clone()), &(user_shares - shares));

        let usdc: Address = env.storage().instance().get(&DataKey::UsdcToken).unwrap();
        token::Client::new(&env, &usdc).transfer(
            &env.current_contract_address(),
            &provider,
            &usdc_out,
        );

        env.events()
            .publish((symbol_short!("WITHDRAW"), provider), (shares, usdc_out));
        Ok(usdc_out)
    }

    // ── Policy Purchase ───────────────────────────────────────────────────────

    /// Preview the premium cost for a proposed insurance policy.
    ///
    /// Checks coverage capacity against configured boundaries and pool reserves.
    pub fn quote_premium(env: Env, params: PolicyParams) -> Result<i128, PoolError> {
        Self::assert_initialized(&env)?;
        let config: PoolConfig = env.storage().instance().get(&DataKey::PoolConfig).unwrap();
        Self::_check_coverage_capacity(&env, &config, params.coverage_amount)?;
        Ok(Self::_calc_premium(&config, &params))
    }

    /// Purchase an insurance policy, transferring the required premium upfront.
    ///
    /// Requires authorization from `holder`. The newly created policy is stored
    /// on-chain and registered with the linked `RefractPolicyRegistry`.
    pub fn buy_policy(env: Env, holder: Address, params: PolicyParams) -> Result<u64, PoolError> {
        holder.require_auth();
        Self::assert_initialized(&env)?;

        let config: PoolConfig = env.storage().instance().get(&DataKey::PoolConfig).unwrap();
        let new_coverage = Self::_check_coverage_capacity(&env, &config, params.coverage_amount)?;

        let premium = Self::_calc_premium(&config, &params);
        let now = env.ledger().timestamp();
        let end_time = now + (params.duration_days as u64) * 86_400;
        let registry_coverage_type = Self::_to_registry_coverage_type(&params.coverage_type);

        // Transfer premium from holder
        let usdc: Address = env.storage().instance().get(&DataKey::UsdcToken).unwrap();
        token::Client::new(&env, &usdc).transfer(
            &holder,
            &env.current_contract_address(),
            &premium,
        );

        // Record in pool capital (premiums accrue to LPs)
        let mut total_cap: i128 = env
            .storage()
            .instance()
            .get(&DataKey::TotalCapital)
            .unwrap_or(0);
        total_cap += premium;
        env.storage()
            .instance()
            .set(&DataKey::TotalCapital, &total_cap);

        let mut total_prem: i128 = env
            .storage()
            .instance()
            .get(&DataKey::TotalPremiums)
            .unwrap_or(0);
        total_prem += premium;
        env.storage()
            .instance()
            .set(&DataKey::TotalPremiums, &total_prem);
        env.storage()
            .instance()
            .set(&DataKey::TotalCoverage, &new_coverage);

        // Create policy
        let id: u64 = env
            .storage()
            .instance()
            .get(&DataKey::NextPolicyId)
            .unwrap_or(0);
        let policy = Policy {
            id,
            holder: holder.clone(),
            coverage_type: params.coverage_type,
            coverage_amount: params.coverage_amount,
            premium_paid: premium,
            trigger_threshold: params.trigger_threshold,
            start_time: now,
            end_time,
            status: PolicyStatus::Active,
            payout_at: None,
        };

        env.storage()
            .persistent()
            .set(&DataKey::Policy(id), &policy);
        env.storage()
            .instance()
            .set(&DataKey::NextPolicyId, &(id + 1));

        let mut user_policies: Vec<u64> = env
            .storage()
            .persistent()
            .get(&DataKey::UserPolicies(holder.clone()))
            .unwrap_or(Vec::new(&env));
        user_policies.push_back(id);
        env.storage()
            .persistent()
            .set(&DataKey::UserPolicies(holder.clone()), &user_policies);

        let registry_addr: Address = env
            .storage()
            .instance()
            .get(&DataKey::PolicyRegistry)
            .ok_or(PoolError::NotInitialized)?;
        let registration = PolicyRegistration {
            policy_id: id,
            holder: holder.clone(),
            coverage_type: registry_coverage_type,
            coverage_amount: params.coverage_amount,
            premium,
            expires_at: end_time,
        };
        let _registered_id: u64 = env.invoke_contract(
            &registry_addr,
            &Symbol::new(&env, "register_policy"),
            Vec::from_array(
                &env,
                [
                    env.current_contract_address().into_val(&env),
                    registration.into_val(&env),
                ],
            ),
        );
        debug_assert_eq!(
            _registered_id, id,
            "registry must echo back the id the pool assigned"
        );

        env.events().publish(
            (symbol_short!("BUY"), holder),
            (id, params.coverage_amount, premium, end_time),
        );

        Ok(id)
    }

    // ── Claims ────────────────────────────────────────────────────────────────

    /// Process a payout for an active policy when the trigger condition is met.
    ///
    /// Permissionless: anyone may call this once oracle readings confirm the trigger.
    /// Settles the full `coverage_amount` directly to the policyholder's address.
    pub fn process_claim(env: Env, policy_id: u64) -> Result<i128, PoolError> {
        let mut policy: Policy = env
            .storage()
            .persistent()
            .get(&DataKey::Policy(policy_id))
            .ok_or(PoolError::PolicyNotFound)?;

        if policy.status != PolicyStatus::Active {
            return Err(PoolError::AlreadyClaimed);
        }

        let now = env.ledger().timestamp();
        if now > policy.end_time {
            return Err(PoolError::PolicyExpired);
        }

        // Read oracle data
        let oracle: Option<OracleData> = env
            .storage()
            .instance()
            .get(&DataKey::OracleData(policy.coverage_type.clone()));

        let triggered = match oracle {
            None => false,
            Some(data) => {
                let fresh = now - data.updated_at < 1_800;
                let triggered_value = match policy.coverage_type {
                    CoverageType::StablecoinDepeg => {
                        data.value < (PRECISION - policy.trigger_threshold * PRECISION / BPS)
                    }
                    CoverageType::MarketCrash => data.value < -policy.trigger_threshold,
                    CoverageType::LiquidationShield => data.value > 0,
                    CoverageType::SmartContractRisk => data.value > 0,
                    CoverageType::FlightDelay => data.value > policy.trigger_threshold,
                };
                fresh && triggered_value
            }
        };

        if !triggered {
            return Err(PoolError::PolicyNotTriggered);
        }

        let payout = policy.coverage_amount;
        policy.status = PolicyStatus::Claimed;
        policy.payout_at = Some(now);
        env.storage()
            .persistent()
            .set(&DataKey::Policy(policy_id), &policy);

        let mut total_cap: i128 = env
            .storage()
            .instance()
            .get(&DataKey::TotalCapital)
            .unwrap_or(0);
        total_cap = (total_cap - payout).max(0);
        env.storage()
            .instance()
            .set(&DataKey::TotalCapital, &total_cap);

        let mut total_cov: i128 = env
            .storage()
            .instance()
            .get(&DataKey::TotalCoverage)
            .unwrap_or(0);
        total_cov = (total_cov - payout).max(0);
        env.storage()
            .instance()
            .set(&DataKey::TotalCoverage, &total_cov);

        let usdc: Address = env.storage().instance().get(&DataKey::UsdcToken).unwrap();
        token::Client::new(&env, &usdc).transfer(
            &env.current_contract_address(),
            &policy.holder,
            &payout,
        );

        Self::_deactivate_in_registry(&env, policy_id);

        env.events().publish(
            (symbol_short!("CLAIM"), policy.holder),
            (policy_id, payout, now),
        );

        Ok(payout)
    }

    /// Sweep a lapsed policy, releasing its locked coverage capacity.
    ///
    /// Permissionless: callable by anyone once a policy's `end_time` has elapsed
    /// without a triggering claim. Reclaims underwriting room for new policies.
    pub fn expire_policy(env: Env, policy_id: u64) -> Result<(), PoolError> {
        let mut policy: Policy = env
            .storage()
            .persistent()
            .get(&DataKey::Policy(policy_id))
            .ok_or(PoolError::PolicyNotFound)?;

        if policy.status != PolicyStatus::Active {
            return Err(PoolError::AlreadyClaimed);
        }

        let now = env.ledger().timestamp();
        if now <= policy.end_time {
            return Err(PoolError::PolicyNotYetExpired);
        }

        policy.status = PolicyStatus::Expired;
        env.storage()
            .persistent()
            .set(&DataKey::Policy(policy_id), &policy);

        let mut total_cov: i128 = env
            .storage()
            .instance()
            .get(&DataKey::TotalCoverage)
            .unwrap_or(0);
        total_cov = (total_cov - policy.coverage_amount).max(0);
        env.storage()
            .instance()
            .set(&DataKey::TotalCoverage, &total_cov);

        Self::_deactivate_in_registry(&env, policy_id);

        env.events()
            .publish((symbol_short!("EXPIRE"), policy.holder), (policy_id, now));

        Ok(())
    }

    // ── Admin ─────────────────────────────────────────────────────────────────

    /// Repoint the RefractPolicyRegistry contract address that this pool indexes policies into.
    ///
    /// Requires administrative authorization.
    pub fn set_policy_registry(
        env: Env,
        caller: Address,
        policy_registry: Address,
    ) -> Result<(), PoolError> {
        Self::require_admin(&env, &caller)?;
        env.storage()
            .instance()
            .set(&DataKey::PolicyRegistry, &policy_registry);

        env.events()
            .publish((symbol_short!("REG_SET"), caller), (policy_registry,));
        Ok(())
    }

    /// Rotate the administrative key authorized to execute admin functions.
    ///
    /// Requires authorization from the current administrator.
    pub fn set_admin(env: Env, caller: Address, new_admin: Address) -> Result<(), PoolError> {
        Self::require_admin(&env, &caller)?;
        env.storage().instance().set(&DataKey::Admin, &new_admin);

        env.events()
            .publish((symbol_short!("ADMIN_SET"),), (new_admin,));
        Ok(())
    }

    /// Replace the pool's operational risk configuration parameters wholesale.
    ///
    /// Requires administrative authorization.
    pub fn set_pool_config(env: Env, caller: Address, config: PoolConfig) -> Result<(), PoolError> {
        Self::require_admin(&env, &caller)?;
        env.storage().instance().set(&DataKey::PoolConfig, &config);

        env.events().publish((symbol_short!("CFG_SET"),), ());
        Ok(())
    }

    // ── Oracle (Admin-controlled, upgradeable to decentralized oracle) ─────────

    /// Update the cached oracle metric reading for a specific coverage category.
    ///
    /// Requires administrative authorization.
    pub fn update_oracle(
        env: Env,
        caller: Address,
        coverage_type: CoverageType,
        value: i128,
    ) -> Result<(), PoolError> {
        Self::require_admin(&env, &caller)?;

        env.storage().instance().set(
            &DataKey::OracleData(coverage_type.clone()),
            &OracleData {
                value,
                updated_at: env.ledger().timestamp(),
            },
        );

        env.events()
            .publish((symbol_short!("ORACLE"), coverage_type), (value,));
        Ok(())
    }

    // ── View Functions ────────────────────────────────────────────────────────

    /// Return comprehensive aggregate pool metrics, utilization, and share pricing.
    pub fn pool_stats(env: Env) -> PoolStats {
        let total_capital: i128 = env
            .storage()
            .instance()
            .get(&DataKey::TotalCapital)
            .unwrap_or(0);
        let total_coverage: i128 = env
            .storage()
            .instance()
            .get(&DataKey::TotalCoverage)
            .unwrap_or(0);
        let total_shares: i128 = env
            .storage()
            .instance()
            .get(&DataKey::TotalShares)
            .unwrap_or(0);
        let config: PoolConfig = env
            .storage()
            .instance()
            .get(&DataKey::PoolConfig)
            .unwrap_or(PoolConfig {
                base_premium_rate_bps: 0,
                max_utilization_bps: 0,
                min_coverage: 0,
                max_coverage: 0,
                lockup_days: 0,
            });

        let utilization_bps = if total_capital == 0 {
            0
        } else {
            (total_coverage * BPS / total_capital) as u32
        };
        let share_price = if total_shares == 0 {
            PRECISION
        } else {
            total_capital * PRECISION / total_shares
        };
        let apy_estimate_bps = config.base_premium_rate_bps * utilization_bps / 10_000;
        let max_coverage_capacity = total_capital * (config.max_utilization_bps as i128) / BPS;
        let available_capacity = (max_coverage_capacity - total_coverage).max(0);

        PoolStats {
            total_capital,
            total_coverage,
            total_shares,
            utilization_bps,
            share_price,
            available_capacity,
            apy_estimate_bps,
        }
    }

    /// Retrieve an individual policy record by its unique identifier.
    pub fn get_policy(env: Env, id: u64) -> Option<Policy> {
        env.storage().persistent().get(&DataKey::Policy(id))
    }

    /// Batch-fetch multiple policies by ID in a single query.
    ///
    /// Skips non-existent policy IDs rather than reverting.
    pub fn get_policies(env: Env, ids: Vec<u64>) -> Vec<Policy> {
        let mut out = Vec::new(&env);
        for id in ids.iter() {
            if let Some(policy) = env
                .storage()
                .persistent()
                .get::<DataKey, Policy>(&DataKey::Policy(id))
            {
                out.push_back(policy);
            }
        }
        out
    }

    /// Retrieve the list of policy IDs associated with a specific user address.
    pub fn user_policies(env: Env, user: Address) -> Vec<u64> {
        env.storage()
            .persistent()
            .get(&DataKey::UserPolicies(user))
            .unwrap_or(Vec::new(&env))
    }

    /// Retrieve the total pool LP share balance for a specific provider.
    pub fn shares_of(env: Env, user: Address) -> i128 {
        env.storage()
            .persistent()
            .get(&DataKey::Shares(user))
            .unwrap_or(0)
    }

    /// Return the Unix timestamp when an LP provider's lockup period will expire.
    ///
    /// Returns `None` if the provider has never deposited.
    pub fn lockup_expires_at(env: Env, provider: Address) -> Option<u64> {
        let last_deposit: u64 = env
            .storage()
            .persistent()
            .get(&DataKey::LastDeposit(provider))?;
        let config: PoolConfig = env.storage().instance().get(&DataKey::PoolConfig).unwrap();
        Some(last_deposit + (config.lockup_days as u64) * 86_400)
    }

    /// Retrieve the address of the secondary Policy Registry currently wired to the pool.
    pub fn policy_registry(env: Env) -> Option<Address> {
        env.storage().instance().get(&DataKey::PolicyRegistry)
    }

    /// Retrieve the current administrator address of the pool.
    pub fn admin(env: Env) -> Option<Address> {
        env.storage().instance().get(&DataKey::Admin)
    }

    /// Retrieve the operational parameters currently active for the pool.
    pub fn pool_config(env: Env) -> Option<PoolConfig> {
        env.storage().instance().get(&DataKey::PoolConfig)
    }

    // ── Internals ─────────────────────────────────────────────────────────────

    /// Translate the pool's own CoverageType into the wire-compatible mirror.
    fn _to_registry_coverage_type(t: &CoverageType) -> RegistryCoverageType {
        match t {
            CoverageType::StablecoinDepeg => RegistryCoverageType::StablecoinDepeg,
            CoverageType::MarketCrash => RegistryCoverageType::MarketCrash,
            CoverageType::LiquidationShield => RegistryCoverageType::LiquidationShield,
            CoverageType::SmartContractRisk => RegistryCoverageType::SmartContractRisk,
            CoverageType::FlightDelay => RegistryCoverageType::FlightDelay,
        }
    }

    /// Deactivate a policy's mirrored record in RefractPolicyRegistry.
    fn _deactivate_in_registry(env: &Env, policy_id: u64) {
        let registry_addr: Option<Address> = env.storage().instance().get(&DataKey::PolicyRegistry);
        let Some(registry_addr) = registry_addr else {
            return;
        };
        let _ = env.try_invoke_contract::<(), soroban_sdk::InvokeError>(
            &registry_addr,
            &Symbol::new(env, "deactivate_policy"),
            Vec::from_array(
                env,
                [
                    env.current_contract_address().into_val(env),
                    policy_id.into_val(env),
                ],
            ),
        );
    }

    /// Calculate policy premium based on coverage amount, base rate, duration, and risk category.
    fn _calc_premium(config: &PoolConfig, params: &PolicyParams) -> i128 {
        let base = params.coverage_amount * (config.base_premium_rate_bps as i128) / BPS;
        let duration_factor = params.duration_days as i128 * PRECISION / 365;
        let risk_multiplier = match params.coverage_type {
            CoverageType::StablecoinDepeg => 100,
            CoverageType::MarketCrash => 150,
            CoverageType::LiquidationShield => 200,
            CoverageType::SmartContractRisk => 300,
            CoverageType::FlightDelay => 80,
        };
        base * duration_factor / PRECISION * risk_multiplier / 100
    }

    /// Compute pool shares to mint for a given deposit amount.
    fn _calc_shares(env: &Env, amount: i128) -> i128 {
        let total_capital: i128 = env
            .storage()
            .instance()
            .get(&DataKey::TotalCapital)
            .unwrap_or(0);
        let total_shares: i128 = env
            .storage()
            .instance()
            .get(&DataKey::TotalShares)
            .unwrap_or(0);
        if total_shares == 0 || total_capital == 0 {
            amount
        } else {
            amount * total_shares / total_capital
        }
    }

    /// Validate coverage capacity against pool configuration and current utilization.
    fn _check_coverage_capacity(
        env: &Env,
        config: &PoolConfig,
        coverage_amount: i128,
    ) -> Result<i128, PoolError> {
        if coverage_amount < config.min_coverage {
            return Err(PoolError::InsufficientCapacity);
        }
        if coverage_amount > config.max_coverage {
            return Err(PoolError::InsufficientCapacity);
        }

        let total_capital: i128 = env
            .storage()
            .instance()
            .get(&DataKey::TotalCapital)
            .unwrap_or(0);
        let total_coverage: i128 = env
            .storage()
            .instance()
            .get(&DataKey::TotalCoverage)
            .unwrap_or(0);
        let new_coverage = total_coverage + coverage_amount;
        let max_coverage_capacity = total_capital * (config.max_utilization_bps as i128) / BPS;

        if new_coverage > max_coverage_capacity {
            return Err(PoolError::InsufficientCapacity);
        }

        Ok(new_coverage)
    }

    /// Calculate capital returned on share redemption and verify post-withdrawal solvency.
    fn _quote_withdrawal(env: &Env, shares: i128) -> Result<i128, PoolError> {
        let total_capital: i128 = env
            .storage()
            .instance()
            .get(&DataKey::TotalCapital)
            .unwrap_or(0);
        let total_coverage: i128 = env
            .storage()
            .instance()
            .get(&DataKey::TotalCoverage)
            .unwrap_or(0);
        let total_shares: i128 = env
            .storage()
            .instance()
            .get(&DataKey::TotalShares)
            .unwrap_or(0);
        let config: PoolConfig = env.storage().instance().get(&DataKey::PoolConfig).unwrap();

        if shares > total_shares {
            return Err(PoolError::InsufficientShares);
        }

        let usdc_out = if total_shares == 0 {
            0
        } else {
            shares * total_capital / total_shares
        };

        let new_capital = total_capital - usdc_out;
        if new_capital > 0 {
            let new_util = total_coverage * BPS / new_capital;
            if new_util > config.max_utilization_bps as i128 {
                return Err(PoolError::CapitalLocked);
            }
        }

        Ok(usdc_out)
    }

    /// Assert that the pool contract has been initialized.
    fn assert_initialized(env: &Env) -> Result<(), PoolError> {
        if !env.storage().instance().has(&DataKey::Initialized) {
            return Err(PoolError::NotInitialized);
        }
        Ok(())
    }

    /// Verify administrator authorization.
    fn require_admin(env: &Env, caller: &Address) -> Result<(), PoolError> {
        caller.require_auth();
        let admin: Address = env
            .storage()
            .instance()
            .get(&DataKey::Admin)
            .ok_or(PoolError::NotInitialized)?;
        if caller != &admin {
            return Err(PoolError::Unauthorized);
        }
        Ok(())
    }
}

#[cfg(test)]
mod test;

#[cfg(test)]
mod pricing_proptest;

use {
    crate::{
        accounts_data_meter::AccountsDataMeter,
        compute_budget::ComputeBudget,
        ic_logger_msg, ic_msg,
        loaded_programs::{LoadedProgram, LoadedProgramType, LoadedProgramsForTxBatch},
        log_collector::LogCollector,
        pre_account::PreAccount,
        stable_log,
        sysvar_cache::SysvarCache,
        timings::{ExecuteDetailsTimings, ExecuteTimings},
    },
    base64::Engine,
    solana_measure::measure::Measure,
    solana_rbpf::{
        ebpf::MM_HEAP_START,
        elf::SBPFVersion,
        memory_region::MemoryMapping,
        vm::{BuiltinFunction, Config, ContextObject, ProgramResult},
    },
    solana_sdk::{
        account::{AccountSharedData, ReadableAccount},
        bpf_loader_deprecated,
        feature_set::{
            check_slice_translation_size, enable_early_verification_of_account_modifications,
            native_programs_consume_cu, FeatureSet,
        },
        hash::Hash,
        instruction::{AccountMeta, InstructionError},
        native_loader,
        pubkey::Pubkey,
        rent::Rent,
        saturating_add_assign,
        clock::Epoch,
        stable_layout::stable_instruction::StableInstruction,
        transaction_context::{
            IndexOfAccount, InstructionAccount, TransactionAccount, TransactionContext,
        },
    },
    std::{
        alloc::Layout,
        cell::RefCell,
        fmt::{self, Debug},
        rc::Rc,
        sync::{atomic::Ordering, Arc},
    },
};

pub extern crate bs58;

use std::env;

use std::backtrace::Backtrace;

// use itertools::Itertools;
use serde::Serialize;
use serde_with::serde_as;
use serde_with::DisplayFromStr;
use std::str::FromStr;

pub type ProcessInstructionWithContext = BuiltinFunction<InvokeContext<'static>>;

/// Adapter so we can unify the interfaces of built-in programs and syscalls
#[macro_export]
macro_rules! declare_process_instruction {
    ($process_instruction:ident, $cu_to_consume:expr, |$invoke_context:ident| $inner:tt) => {
        pub fn $process_instruction(
            invoke_context: &mut $crate::invoke_context::InvokeContext,
            _arg0: u64,
            _arg1: u64,
            _arg2: u64,
            _arg3: u64,
            _arg4: u64,
            _memory_mapping: &mut $crate::solana_rbpf::memory_region::MemoryMapping,
            result: &mut $crate::solana_rbpf::vm::ProgramResult,
        ) {
            fn process_instruction_inner(
                $invoke_context: &mut $crate::invoke_context::InvokeContext,
            ) -> std::result::Result<(), solana_sdk::instruction::InstructionError> {
                $inner
            }
            let consumption_result = if $cu_to_consume > 0
                && invoke_context
                    .feature_set
                    .is_active(&solana_sdk::feature_set::native_programs_consume_cu::id())
            {
                invoke_context.consume_checked($cu_to_consume)
            } else {
                Ok(())
            };
            *result = consumption_result
                .and_then(|_| {
                    process_instruction_inner(invoke_context)
                        .map(|_| 0)
                        .map_err(|err| Box::new(err) as Box<dyn std::error::Error>)
                })
                .into();
        }
    };
}

impl<'a> ContextObject for InvokeContext<'a> {
    fn trace(&mut self, state: [u64; 12]) {
        self.syscall_context
            .last_mut()
            .unwrap()
            .as_mut()
            .unwrap()
            .trace_log
            .push(state);
    }

    fn consume(&mut self, amount: u64) {
        // 1 to 1 instruction to compute unit mapping
        // ignore overflow, Ebpf will bail if exceeded
        let mut compute_meter = self.compute_meter.borrow_mut();
        *compute_meter = compute_meter.saturating_sub(amount);
    }

    fn get_remaining(&self) -> u64 {
        *self.compute_meter.borrow()
    }
}

#[derive(Clone, PartialEq, Eq, Debug)]
pub struct AllocErr;
impl fmt::Display for AllocErr {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.write_str("Error: Memory allocation failed")
    }
}

pub struct BpfAllocator {
    len: u64,
    pos: u64,
}

impl BpfAllocator {
    pub fn new(len: u64) -> Self {
        Self { len, pos: 0 }
    }

    pub fn alloc(&mut self, layout: Layout) -> Result<u64, AllocErr> {
        let bytes_to_align = (self.pos as *const u8).align_offset(layout.align()) as u64;
        if self
            .pos
            .saturating_add(bytes_to_align)
            .saturating_add(layout.size() as u64)
            <= self.len
        {
            self.pos = self.pos.saturating_add(bytes_to_align);
            let addr = MM_HEAP_START.saturating_add(self.pos);
            self.pos = self.pos.saturating_add(layout.size() as u64);
            Ok(addr)
        } else {
            Err(AllocErr)
        }
    }
}

pub struct SyscallContext {
    pub allocator: BpfAllocator,
    pub accounts_metadata: Vec<SerializedAccountMetadata>,
    pub trace_log: Vec<[u64; 12]>,
}

#[derive(Debug, Clone)]
pub struct SerializedAccountMetadata {
    pub original_data_len: usize,
}

pub struct InvokeContext<'a> {
    pub transaction_context: &'a mut TransactionContext,
    rent: Rent,
    pre_accounts: Vec<PreAccount>,
    sysvar_cache: &'a SysvarCache,
    log_collector: Option<Rc<RefCell<LogCollector>>>,
    compute_budget: ComputeBudget,
    current_compute_budget: ComputeBudget,
    compute_meter: RefCell<u64>,
    accounts_data_meter: AccountsDataMeter,
    pub programs_loaded_for_tx_batch: &'a LoadedProgramsForTxBatch,
    pub programs_modified_by_tx: &'a mut LoadedProgramsForTxBatch,
    pub programs_updated_only_for_global_cache: &'a mut LoadedProgramsForTxBatch,
    pub feature_set: Arc<FeatureSet>,
    pub timings: ExecuteDetailsTimings,
    pub blockhash: Hash,
    pub lamports_per_signature: u64,
    pub syscall_context: Vec<Option<SyscallContext>>,
    traces: Vec<Vec<[u64; 12]>>,
}

impl<'a> InvokeContext<'a> {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        transaction_context: &'a mut TransactionContext,
        rent: Rent,
        sysvar_cache: &'a SysvarCache,
        log_collector: Option<Rc<RefCell<LogCollector>>>,
        compute_budget: ComputeBudget,
        programs_loaded_for_tx_batch: &'a LoadedProgramsForTxBatch,
        programs_modified_by_tx: &'a mut LoadedProgramsForTxBatch,
        programs_updated_only_for_global_cache: &'a mut LoadedProgramsForTxBatch,
        feature_set: Arc<FeatureSet>,
        blockhash: Hash,
        lamports_per_signature: u64,
        prev_accounts_data_len: u64,
    ) -> Self {
        Self {
            transaction_context,
            rent,
            pre_accounts: Vec::new(),
            sysvar_cache,
            log_collector,
            current_compute_budget: compute_budget,
            compute_budget,
            compute_meter: RefCell::new(compute_budget.compute_unit_limit),
            accounts_data_meter: AccountsDataMeter::new(prev_accounts_data_len),
            programs_loaded_for_tx_batch,
            programs_modified_by_tx,
            programs_updated_only_for_global_cache,
            feature_set,
            timings: ExecuteDetailsTimings::default(),
            blockhash,
            lamports_per_signature,
            syscall_context: Vec::new(),
            traces: Vec::new(),
        }
    }

    pub fn find_program_in_cache(&self, pubkey: &Pubkey) -> Option<Arc<LoadedProgram>> {
        // First lookup the cache of the programs modified by the current transaction. If not found, lookup
        // the cache of the cache of the programs that are loaded for the transaction batch.
        self.programs_modified_by_tx
            .find(pubkey)
            .or_else(|| self.programs_loaded_for_tx_batch.find(pubkey))
    }

    /// Push a stack frame onto the invocation stack
    pub fn push(&mut self) -> Result<(), InstructionError> {
        let instruction_context = self
            .transaction_context
            .get_instruction_context_at_index_in_trace(
                self.transaction_context.get_instruction_trace_length(),
            )?;
        let program_id = instruction_context
            .get_last_program_key(self.transaction_context)
            .map_err(|_| InstructionError::UnsupportedProgramId)?;
        if self
            .transaction_context
            .get_instruction_context_stack_height()
            == 0
        {
            self.current_compute_budget = self.compute_budget;

            if !self
                .feature_set
                .is_active(&enable_early_verification_of_account_modifications::id())
            {
                self.pre_accounts = Vec::with_capacity(
                    instruction_context.get_number_of_instruction_accounts() as usize,
                );
                for instruction_account_index in
                    0..instruction_context.get_number_of_instruction_accounts()
                {
                    if instruction_context
                        .is_instruction_account_duplicate(instruction_account_index)?
                        .is_some()
                    {
                        continue; // Skip duplicate account
                    }
                    let index_in_transaction = instruction_context
                        .get_index_of_instruction_account_in_transaction(
                            instruction_account_index,
                        )?;
                    if index_in_transaction >= self.transaction_context.get_number_of_accounts() {
                        return Err(InstructionError::MissingAccount);
                    }
                    let account = self
                        .transaction_context
                        .get_account_at_index(index_in_transaction)?
                        .borrow()
                        .clone();
                    self.pre_accounts.push(PreAccount::new(
                        self.transaction_context
                            .get_key_of_account_at_index(index_in_transaction)?,
                        account,
                    ));
                }
            }
        } else {
            let contains = (0..self
                .transaction_context
                .get_instruction_context_stack_height())
                .any(|level| {
                    self.transaction_context
                        .get_instruction_context_at_nesting_level(level)
                        .and_then(|instruction_context| {
                            instruction_context
                                .try_borrow_last_program_account(self.transaction_context)
                        })
                        .map(|program_account| program_account.get_key() == program_id)
                        .unwrap_or(false)
                });
            let is_last = self
                .transaction_context
                .get_current_instruction_context()
                .and_then(|instruction_context| {
                    instruction_context.try_borrow_last_program_account(self.transaction_context)
                })
                .map(|program_account| program_account.get_key() == program_id)
                .unwrap_or(false);
            if contains && !is_last {
                // Reentrancy not allowed unless caller is calling itself
                return Err(InstructionError::ReentrancyNotAllowed);
            }
        }

        self.syscall_context.push(None);
        self.transaction_context.push()
    }

    /// Pop a stack frame from the invocation stack
    pub fn pop(&mut self) -> Result<(), InstructionError> {
        if let Some(Some(syscall_context)) = self.syscall_context.pop() {
            self.traces.push(syscall_context.trace_log);
        }
        self.transaction_context.pop()
    }

    /// Current height of the invocation stack, top level instructions are height
    /// `solana_sdk::instruction::TRANSACTION_LEVEL_STACK_HEIGHT`
    pub fn get_stack_height(&self) -> usize {
        self.transaction_context
            .get_instruction_context_stack_height()
    }

    /// Verify the results of an instruction
    ///
    /// Note: `instruction_accounts` must be the same as passed to `InvokeContext::push()`,
    /// so that they match the order of `pre_accounts`.
    fn verify(
        &mut self,
        instruction_accounts: &[InstructionAccount],
        program_indices: &[IndexOfAccount],
    ) -> Result<(), InstructionError> {
        let instruction_context = self
            .transaction_context
            .get_current_instruction_context()
            .map_err(|_| InstructionError::CallDepth)?;
        let program_id = instruction_context
            .get_last_program_key(self.transaction_context)
            .map_err(|_| InstructionError::CallDepth)?;

        // Verify all executable accounts have zero outstanding refs
        for account_index in program_indices.iter() {
            self.transaction_context
                .get_account_at_index(*account_index)?
                .try_borrow_mut()
                .map_err(|_| InstructionError::AccountBorrowOutstanding)?;
        }

        // Verify the per-account instruction results
        let (mut pre_sum, mut post_sum) = (0_u128, 0_u128);
        let mut pre_account_index = 0;
        for (instruction_account_index, instruction_account) in
            instruction_accounts.iter().enumerate()
        {
            if instruction_account_index as IndexOfAccount != instruction_account.index_in_callee {
                continue; // Skip duplicate account
            }
            {
                // Verify account has no outstanding references
                let _ = self
                    .transaction_context
                    .get_account_at_index(instruction_account.index_in_transaction)?
                    .try_borrow_mut()
                    .map_err(|_| InstructionError::AccountBorrowOutstanding)?;
            }
            let pre_account = &self
                .pre_accounts
                .get(pre_account_index)
                .ok_or(InstructionError::NotEnoughAccountKeys)?;
            pre_account_index = pre_account_index.saturating_add(1);
            let account = self
                .transaction_context
                .get_account_at_index(instruction_account.index_in_transaction)?
                .borrow();
            pre_account
                .verify(
                    program_id,
                    instruction_account.is_writable,
                    &self.rent,
                    &account,
                    &mut self.timings,
                    true,
                )
                .map_err(|err| {
                    ic_logger_msg!(
                        self.log_collector,
                        "failed to verify account {}: {}",
                        pre_account.key(),
                        err
                    );
                    err
                })?;
            pre_sum = pre_sum
                .checked_add(u128::from(pre_account.lamports()))
                .ok_or(InstructionError::UnbalancedInstruction)?;
            post_sum = post_sum
                .checked_add(u128::from(account.lamports()))
                .ok_or(InstructionError::UnbalancedInstruction)?;

            let pre_data_len = pre_account.data().len() as i64;
            let post_data_len = account.data().len() as i64;
            let data_len_delta = post_data_len.saturating_sub(pre_data_len);
            self.accounts_data_meter
                .adjust_delta_unchecked(data_len_delta);
        }

        // Verify that the total sum of all the lamports did not change
        if pre_sum != post_sum {
            return Err(InstructionError::UnbalancedInstruction);
        }
        Ok(())
    }

    /// Verify and update PreAccount state based on program execution
    ///
    /// Note: `instruction_accounts` must be the same as passed to `InvokeContext::push()`,
    /// so that they match the order of `pre_accounts`.
    fn verify_and_update(
        &mut self,
        instruction_accounts: &[InstructionAccount],
        before_instruction_context_push: bool,
    ) -> Result<(), InstructionError> {
        let transaction_context = &self.transaction_context;
        let instruction_context = transaction_context.get_current_instruction_context()?;
        let program_id = instruction_context
            .get_last_program_key(transaction_context)
            .map_err(|_| InstructionError::CallDepth)?;

        // Verify the per-account instruction results
        let (mut pre_sum, mut post_sum) = (0_u128, 0_u128);
        for (instruction_account_index, instruction_account) in
            instruction_accounts.iter().enumerate()
        {
            if instruction_account_index as IndexOfAccount != instruction_account.index_in_callee {
                continue; // Skip duplicate account
            }
            if instruction_account.index_in_transaction
                < transaction_context.get_number_of_accounts()
            {
                let key = transaction_context
                    .get_key_of_account_at_index(instruction_account.index_in_transaction)?;
                let account = transaction_context
                    .get_account_at_index(instruction_account.index_in_transaction)?;
                let is_writable = if before_instruction_context_push {
                    instruction_context
                        .is_instruction_account_writable(instruction_account.index_in_caller)?
                } else {
                    instruction_account.is_writable
                };
                // Find the matching PreAccount
                for pre_account in self.pre_accounts.iter_mut() {
                    if key == pre_account.key() {
                        {
                            // Verify account has no outstanding references
                            let _ = account
                                .try_borrow_mut()
                                .map_err(|_| InstructionError::AccountBorrowOutstanding)?;
                        }
                        let account = account.borrow();
                        pre_account
                            .verify(
                                program_id,
                                is_writable,
                                &self.rent,
                                &account,
                                &mut self.timings,
                                false,
                            )
                            .map_err(|err| {
                                ic_logger_msg!(
                                    self.log_collector,
                                    "failed to verify account {}: {}",
                                    key,
                                    err
                                );
                                err
                            })?;
                        pre_sum = pre_sum
                            .checked_add(u128::from(pre_account.lamports()))
                            .ok_or(InstructionError::UnbalancedInstruction)?;
                        post_sum = post_sum
                            .checked_add(u128::from(account.lamports()))
                            .ok_or(InstructionError::UnbalancedInstruction)?;
                        if is_writable && !pre_account.executable() {
                            pre_account.update(account.clone());
                        }

                        let pre_data_len = pre_account.data().len() as i64;
                        let post_data_len = account.data().len() as i64;
                        let data_len_delta = post_data_len.saturating_sub(pre_data_len);
                        self.accounts_data_meter
                            .adjust_delta_unchecked(data_len_delta);

                        break;
                    }
                }
            }
        }

        // Verify that the total sum of all the lamports did not change
        if pre_sum != post_sum {
            return Err(InstructionError::UnbalancedInstruction);
        }
        Ok(())
    }

    /// Entrypoint for a cross-program invocation from a builtin program
    pub fn native_invoke(
        &mut self,
        instruction: StableInstruction,
        signers: &[Pubkey],
    ) -> Result<(), InstructionError> {
        let (instruction_accounts, program_indices) =
            self.prepare_instruction(&instruction, signers)?;
        let mut compute_units_consumed = 0;
        self.process_instruction(
            &instruction.data,
            &instruction_accounts,
            &program_indices,
            &mut compute_units_consumed,
            &mut ExecuteTimings::default(),
        )?;
        Ok(())
    }

    /// Helper to prepare for process_instruction()
    #[allow(clippy::type_complexity)]
    pub fn prepare_instruction(
        &mut self,
        instruction: &StableInstruction,
        signers: &[Pubkey],
    ) -> Result<(Vec<InstructionAccount>, Vec<IndexOfAccount>), InstructionError> {
        // Finds the index of each account in the instruction by its pubkey.
        // Then normalizes / unifies the privileges of duplicate accounts.
        // Note: This is an O(n^2) algorithm,
        // but performed on a very small slice and requires no heap allocations.
        let instruction_context = self.transaction_context.get_current_instruction_context()?;
        let mut deduplicated_instruction_accounts: Vec<InstructionAccount> = Vec::new();
        let mut duplicate_indicies = Vec::with_capacity(instruction.accounts.len());
        for (instruction_account_index, account_meta) in instruction.accounts.iter().enumerate() {
            let index_in_transaction = self
                .transaction_context
                .find_index_of_account(&account_meta.pubkey)
                .ok_or_else(|| {
                    ic_msg!(
                        self,
                        "Instruction references an unknown account {}",
                        account_meta.pubkey,
                    );
                    InstructionError::MissingAccount
                })?;
            if let Some(duplicate_index) =
                deduplicated_instruction_accounts
                    .iter()
                    .position(|instruction_account| {
                        instruction_account.index_in_transaction == index_in_transaction
                    })
            {
                duplicate_indicies.push(duplicate_index);
                let instruction_account = deduplicated_instruction_accounts
                    .get_mut(duplicate_index)
                    .ok_or(InstructionError::NotEnoughAccountKeys)?;
                instruction_account.is_signer |= account_meta.is_signer;
                instruction_account.is_writable |= account_meta.is_writable;
            } else {
                let index_in_caller = instruction_context
                    .find_index_of_instruction_account(
                        self.transaction_context,
                        &account_meta.pubkey,
                    )
                    .ok_or_else(|| {
                        ic_msg!(
                            self,
                            "Instruction references an unknown account {}",
                            account_meta.pubkey,
                        );
                        InstructionError::MissingAccount
                    })?;
                duplicate_indicies.push(deduplicated_instruction_accounts.len());
                deduplicated_instruction_accounts.push(InstructionAccount {
                    index_in_transaction,
                    index_in_caller,
                    index_in_callee: instruction_account_index as IndexOfAccount,
                    is_signer: account_meta.is_signer,
                    is_writable: account_meta.is_writable,
                });
            }
        }
        for instruction_account in deduplicated_instruction_accounts.iter() {
            let borrowed_account = instruction_context.try_borrow_instruction_account(
                self.transaction_context,
                instruction_account.index_in_caller,
            )?;

            // Readonly in caller cannot become writable in callee
            if instruction_account.is_writable && !borrowed_account.is_writable() {
                ic_msg!(
                    self,
                    "{}'s writable privilege escalated",
                    borrowed_account.get_key(),
                );
                return Err(InstructionError::PrivilegeEscalation);
            }

            // To be signed in the callee,
            // it must be either signed in the caller or by the program
            if instruction_account.is_signer
                && !(borrowed_account.is_signer() || signers.contains(borrowed_account.get_key()))
            {
                ic_msg!(
                    self,
                    "{}'s signer privilege escalated",
                    borrowed_account.get_key()
                );
                return Err(InstructionError::PrivilegeEscalation);
            }
        }
        let instruction_accounts = duplicate_indicies
            .into_iter()
            .map(|duplicate_index| {
                Ok(deduplicated_instruction_accounts
                    .get(duplicate_index)
                    .ok_or(InstructionError::NotEnoughAccountKeys)?
                    .clone())
            })
            .collect::<Result<Vec<InstructionAccount>, InstructionError>>()?;

        // Find and validate executables / program accounts
        let callee_program_id = instruction.program_id;
        let program_account_index = instruction_context
            .find_index_of_instruction_account(self.transaction_context, &callee_program_id)
            .ok_or_else(|| {
                ic_msg!(self, "Unknown program {}", callee_program_id);
                InstructionError::MissingAccount
            })?;
        let borrowed_program_account = instruction_context
            .try_borrow_instruction_account(self.transaction_context, program_account_index)?;
        if !borrowed_program_account.is_executable() {
            ic_msg!(self, "Account {} is not executable", callee_program_id);
            return Err(InstructionError::AccountNotExecutable);
        }

        Ok((
            instruction_accounts,
            vec![borrowed_program_account.get_index_in_transaction()],
        ))
    }

    /// Processes an instruction and returns how many compute units were used
    pub fn process_instruction(
        &mut self,
        instruction_data: &[u8],
        instruction_accounts: &[InstructionAccount],
        program_indices: &[IndexOfAccount],
        compute_units_consumed: &mut u64,
        timings: &mut ExecuteTimings,
    ) -> Result<(), InstructionError> {
        *compute_units_consumed = 0;

        let nesting_level = self
            .transaction_context
            .get_instruction_context_stack_height();
        let is_top_level_instruction = nesting_level == 0;
        if !is_top_level_instruction
            && !self
                .feature_set
                .is_active(&enable_early_verification_of_account_modifications::id())
        {
            // Verify the calling program hasn't misbehaved
            let mut verify_caller_time = Measure::start("verify_caller_time");
            let verify_caller_result = self.verify_and_update(instruction_accounts, true);
            verify_caller_time.stop();
            saturating_add_assign!(
                timings
                    .execute_accessories
                    .process_instructions
                    .verify_caller_us,
                verify_caller_time.as_us()
            );
            verify_caller_result?;
        }

        self.transaction_context
            .get_next_instruction_context()?
            .configure(program_indices, instruction_accounts, instruction_data);
        self.push()?;
        self.process_executable_chain(compute_units_consumed, timings)
            .and_then(|_| {
                if self
                    .feature_set
                    .is_active(&enable_early_verification_of_account_modifications::id())
                {
                    Ok(())
                } else {
                    // Verify the called program has not misbehaved
                    let mut verify_callee_time = Measure::start("verify_callee_time");
                    let result = if is_top_level_instruction {
                        self.verify(instruction_accounts, program_indices)
                    } else {
                        self.verify_and_update(instruction_accounts, false)
                    };
                    verify_callee_time.stop();
                    saturating_add_assign!(
                        timings
                            .execute_accessories
                            .process_instructions
                            .verify_callee_us,
                        verify_callee_time.as_us()
                    );
                    result
                }
            })
            // MUST pop if and only if `push` succeeded, independent of `result`.
            // Thus, the `.and()` instead of an `.and_then()`.
            .and(self.pop())
    }

    /// Calls the instruction's program entrypoint method
    fn process_executable_chain(
        &mut self,
        compute_units_consumed: &mut u64,
        timings: &mut ExecuteTimings,
    ) -> Result<(), InstructionError> {
        let instruction_context = self.transaction_context.get_current_instruction_context()?;
        let mut process_executable_chain_time = Measure::start("process_executable_chain_time");

        let builtin_id = {
            let borrowed_root_account = instruction_context
                .try_borrow_program_account(self.transaction_context, 0)
                .map_err(|_| InstructionError::UnsupportedProgramId)?;
            let owner_id = borrowed_root_account.get_owner();
            if native_loader::check_id(owner_id) {
                *borrowed_root_account.get_key()
            } else {
                *owner_id
            }
        };

        // The Murmur3 hash value (used by RBPF) of the string "entrypoint"
        const ENTRYPOINT_KEY: u32 = 0x71E3CF81;
        let entry = self
            .programs_loaded_for_tx_batch
            .find(&builtin_id)
            .ok_or(InstructionError::UnsupportedProgramId)?;
        let process_instruction = match &entry.program {
            LoadedProgramType::Builtin(program) => program
                .lookup_function(ENTRYPOINT_KEY)
                .map(|(_name, process_instruction)| process_instruction),
            _ => None,
        }
        .ok_or(InstructionError::UnsupportedProgramId)?;
        entry.ix_usage_counter.fetch_add(1, Ordering::Relaxed);

        let program_id = *instruction_context.get_last_program_key(self.transaction_context)?;
        self.transaction_context
            .set_return_data(program_id, Vec::new())?;
        let logger = self.get_log_collector();
        stable_log::program_invoke(&logger, &program_id, self.get_stack_height());
        let pre_remaining_units = self.get_remaining();
        let mock_config = Config::default();
        let mut mock_memory_mapping =
            MemoryMapping::new(Vec::new(), &mock_config, &SBPFVersion::V2).unwrap();
        let mut result = ProgramResult::Ok(0);
        process_instruction(
            // Removes lifetime tracking
            unsafe { std::mem::transmute::<&mut InvokeContext, &mut InvokeContext>(self) },
            0,
            0,
            0,
            0,
            0,
            &mut mock_memory_mapping,
            &mut result,
        );
        let result = match result {
            ProgramResult::Ok(_) => {
                stable_log::program_success(&logger, &program_id);
                Ok(())
            }
            ProgramResult::Err(err) => {
                stable_log::program_failure(&logger, &program_id, err.as_ref());
                if let Some(err) = err.downcast_ref::<InstructionError>() {
                    Err(err.clone())
                } else {
                    Err(InstructionError::ProgramFailedToComplete)
                }
            }
        };
        let post_remaining_units = self.get_remaining();
        *compute_units_consumed = pre_remaining_units.saturating_sub(post_remaining_units);

        if builtin_id == program_id
            && result.is_ok()
            && *compute_units_consumed == 0
            && self
                .feature_set
                .is_active(&native_programs_consume_cu::id())
        {
            return Err(InstructionError::BuiltinProgramsMustConsumeComputeUnits);
        }

        process_executable_chain_time.stop();
        saturating_add_assign!(
            timings
                .execute_accessories
                .process_instructions
                .process_executable_chain_us,
            process_executable_chain_time.as_us()
        );
        result
    }

    /// Get this invocation's LogCollector
    pub fn get_log_collector(&self) -> Option<Rc<RefCell<LogCollector>>> {
        self.log_collector.clone()
    }

    /// Consume compute units
    pub fn consume_checked(&self, amount: u64) -> Result<(), Box<dyn std::error::Error>> {
        let mut compute_meter = self.compute_meter.borrow_mut();
        let exceeded = *compute_meter < amount;
        *compute_meter = compute_meter.saturating_sub(amount);
        if exceeded {
            return Err(Box::new(InstructionError::ComputationalBudgetExceeded));
        }
        Ok(())
    }

    /// Set compute units
    ///
    /// Only use for tests and benchmarks
    pub fn mock_set_remaining(&self, remaining: u64) {
        *self.compute_meter.borrow_mut() = remaining;
    }

    /// Get this invocation's AccountsDataMeter
    pub fn get_accounts_data_meter(&self) -> &AccountsDataMeter {
        &self.accounts_data_meter
    }

    /// Get this invocation's compute budget
    pub fn get_compute_budget(&self) -> &ComputeBudget {
        &self.current_compute_budget
    }

    /// Get cached sysvars
    pub fn get_sysvar_cache(&self) -> &SysvarCache {
        self.sysvar_cache
    }

    // Should alignment be enforced during user pointer translation
    pub fn get_check_aligned(&self) -> bool {
        self.transaction_context
            .get_current_instruction_context()
            .and_then(|instruction_context| {
                let program_account =
                    instruction_context.try_borrow_last_program_account(self.transaction_context);
                debug_assert!(program_account.is_ok());
                program_account
            })
            .map(|program_account| *program_account.get_owner() != bpf_loader_deprecated::id())
            .unwrap_or(true)
    }

    // Set should type size be checked during user pointer translation
    pub fn get_check_size(&self) -> bool {
        self.feature_set
            .is_active(&check_slice_translation_size::id())
    }

    // Set this instruction syscall context
    pub fn set_syscall_context(
        &mut self,
        syscall_context: SyscallContext,
    ) -> Result<(), InstructionError> {
        *self
            .syscall_context
            .last_mut()
            .ok_or(InstructionError::CallDepth)? = Some(syscall_context);
        Ok(())
    }

    // Get this instruction's SyscallContext
    pub fn get_syscall_context(&self) -> Result<&SyscallContext, InstructionError> {
        self.syscall_context
            .last()
            .and_then(|syscall_context| syscall_context.as_ref())
            .ok_or(InstructionError::CallDepth)
    }

    // Get this instruction's SyscallContext
    pub fn get_syscall_context_mut(&mut self) -> Result<&mut SyscallContext, InstructionError> {
        self.syscall_context
            .last_mut()
            .and_then(|syscall_context| syscall_context.as_mut())
            .ok_or(InstructionError::CallDepth)
    }

    /// Return a references to traces
    pub fn get_traces(&self) -> &Vec<Vec<[u64; 12]>> {
        &self.traces
    }
}

#[macro_export]
macro_rules! with_mock_invoke_context {
    (
        $invoke_context:ident,
        $transaction_context:ident,
        $transaction_accounts:expr $(,)?
    ) => {
        use {
            solana_sdk::{
                account::ReadableAccount, feature_set::FeatureSet, hash::Hash, sysvar::rent::Rent,
                transaction_context::TransactionContext,
            },
            std::sync::Arc,
            $crate::{
                compute_budget::ComputeBudget, invoke_context::InvokeContext,
                loaded_programs::LoadedProgramsForTxBatch, log_collector::LogCollector,
                sysvar_cache::SysvarCache,
            },
        };
        let compute_budget = ComputeBudget::default();
        let mut $transaction_context = TransactionContext::new(
            $transaction_accounts,
            Some(Rent::default()),
            compute_budget.max_invoke_stack_height,
            compute_budget.max_instruction_trace_length,
        );
        $transaction_context.enable_cap_accounts_data_allocations_per_transaction();
        let mut sysvar_cache = SysvarCache::default();
        sysvar_cache.fill_missing_entries(|pubkey, callback| {
            for index in 0..$transaction_context.get_number_of_accounts() {
                if $transaction_context
                    .get_key_of_account_at_index(index)
                    .unwrap()
                    == pubkey
                {
                    callback(
                        $transaction_context
                            .get_account_at_index(index)
                            .unwrap()
                            .borrow()
                            .data(),
                    );
                }
            }
        });
        let programs_loaded_for_tx_batch = LoadedProgramsForTxBatch::default();
        let mut programs_modified_by_tx = LoadedProgramsForTxBatch::default();
        let mut programs_updated_only_for_global_cache = LoadedProgramsForTxBatch::default();
        let mut $invoke_context = InvokeContext::new(
            &mut $transaction_context,
            Rent::default(),
            &sysvar_cache,
            Some(LogCollector::new_ref()),
            compute_budget,
            &programs_loaded_for_tx_batch,
            &mut programs_modified_by_tx,
            &mut programs_updated_only_for_global_cache,
            Arc::new(FeatureSet::all_enabled()),
            Hash::default(),
            0,
            0,
        );
    };
}

#[serde_as]
#[derive(Serialize)]
struct TestTransactionAccount {
    #[serde_as(as = "DisplayFromStr")]
    pubkey: Pubkey,
    shared_data: TestAccountSharedData,
}

#[serde_with::serde_as]
#[derive(Serialize)]
struct TestAccountSharedData {
    /// lamports in the account
    lamports: u64,
    /// data held in this account
    #[serde(with = "hex_serde")]
    data: Vec<u8>,
    /// the program that owns this account. If executable, the program that loads this account.
    #[serde_as(as = "DisplayFromStr")]
    owner: Pubkey,
    /// this account's data contains a loaded program (and is now read-only)
    executable: bool,
    /// the epoch at which this account will next owe rent
    rent_epoch: Epoch,
}

#[serde_as]
#[derive(Serialize)]
struct TestInstructionAccount {
    #[serde_as(as = "DisplayFromStr")]
    pub index_in_transaction: u16,
    pub index_in_caller: u16,
    pub index_in_callee: u16,
    pub is_signer: bool,
    pub is_writable: bool,
}

#[serde_as]
#[derive(Serialize)]
pub struct TestSysvarCache {
    clock: String,
    epoch_schedule: String,
    epoch_rewards: String,
    fees: String,
    rent: String,
    slot_hashes: String,
    recent_blockhashes: String,
    stake_history: String,
    last_restart_slot: String,
}

#[serde_as]
#[derive(Serialize)]
struct TestCase {
    name: String,
    #[serde_as(as = "DisplayFromStr")]
    program_id: Pubkey,
    #[serde(with = "hex_serde")]
    instruction_data: Vec<u8>,
    feature_set: String,
    sysvar_cache: TestSysvarCache,
    backtrace: String,
    transaction_accounts: Vec<TestTransactionAccount>,
    resulting_accounts: Vec<TestAccountSharedData>,
    instruction_accounts: Vec<TestInstructionAccount>,
    expected_result: Result<(), InstructionError>,
}

fn base64_encode<T: serde::Serialize,E>(val: Result<T,E>) -> String {
    let res = match &val {
        Ok(r) => bincode::serialize(r),
        Err(_) => Ok(Vec::new())
    };

    base64::engine::general_purpose::STANDARD.encode(res.unwrap())
}

pub fn mock_process_instruction<F: FnMut(&mut InvokeContext), G: FnMut(&mut InvokeContext)>(
    loader_id: &Pubkey,
    mut program_indices: Vec<IndexOfAccount>,
    instruction_data: &[u8],
    mut transaction_accounts: Vec<TransactionAccount>,
    instruction_account_metas: Vec<AccountMeta>,
    mut expected_result: Result<(), InstructionError>,
    process_instruction: ProcessInstructionWithContext,
    mut pre_adjustments: F,
    mut post_adjustments: G,
) -> Vec<AccountSharedData> {
    let before : Vec<TestTransactionAccount> = transaction_accounts.clone().into_iter().map(|(pubkey, shared_data)| {
        TestTransactionAccount { pubkey, shared_data: TestAccountSharedData { lamports: shared_data.lamports(), data: shared_data.data().to_vec(), owner: *shared_data.owner(), executable: shared_data.executable(), rent_epoch: shared_data.rent_epoch() } }
    }).collect();
    let mut instruction_accounts: Vec<InstructionAccount> =
        Vec::with_capacity(instruction_account_metas.len());
    for (instruction_account_index, account_meta) in instruction_account_metas.iter().enumerate() {
        let index_in_transaction = transaction_accounts
            .iter()
            .position(|(key, _account)| *key == account_meta.pubkey)
            .unwrap_or(transaction_accounts.len())
            as IndexOfAccount;
        let index_in_callee = instruction_accounts
            .get(0..instruction_account_index)
            .unwrap()
            .iter()
            .position(|instruction_account| {
                instruction_account.index_in_transaction == index_in_transaction
            })
            .unwrap_or(instruction_account_index) as IndexOfAccount;
        instruction_accounts.push(InstructionAccount {
            index_in_transaction,
            index_in_caller: index_in_transaction,
            index_in_callee,
            is_signer: account_meta.is_signer,
            is_writable: account_meta.is_writable,
        });
    }
    program_indices.insert(0, transaction_accounts.len() as IndexOfAccount);
    let processor_account = AccountSharedData::new(0, 0, &native_loader::id());
    transaction_accounts.push((*loader_id, processor_account));
    with_mock_invoke_context!(invoke_context, transaction_context, transaction_accounts);
    let mut programs_loaded_for_tx_batch = LoadedProgramsForTxBatch::default();
    programs_loaded_for_tx_batch.replenish(
        *loader_id,
        Arc::new(LoadedProgram::new_builtin(0, 0, process_instruction)),
    );
    invoke_context.programs_loaded_for_tx_batch = &programs_loaded_for_tx_batch;
    pre_adjustments(&mut invoke_context);

    let sysvar_cache = invoke_context.get_sysvar_cache();
    let tsvc = TestSysvarCache {
        clock: base64_encode(sysvar_cache.get_clock()),
        epoch_schedule: base64_encode(sysvar_cache.get_epoch_schedule()),
        epoch_rewards: base64_encode(sysvar_cache.get_epoch_rewards()),
        fees: base64_encode(sysvar_cache.get_fees()),
        rent: base64_encode(sysvar_cache.get_rent()),
        slot_hashes: base64_encode(sysvar_cache.get_slot_hashes()),
        recent_blockhashes: base64_encode(sysvar_cache.get_recent_blockhashes()),
        stake_history: base64_encode(sysvar_cache.get_stake_history()),
        last_restart_slot: base64_encode(sysvar_cache.get_last_restart_slot()),
    };

    let mainnet =
    match env::var("MAINNET") {
        Ok(_val) => true,
        Err(_e) => false,
    };

    if mainnet {
        match Arc::get_mut(&mut invoke_context.feature_set) {
            // jq '.[] | .pubkey | "                nfs.deactivate(&Pubkey::from_str(\"\(.)\").unwrap());"' -r src/flamenco/features/feature_map.json
            // oh solana labs ... oh josh ...
            Some(nfs) => {
                let active_features = nfs.active.iter().map(|(pubkey, _)| pubkey.clone()).collect::<Vec<_>>();
                for feature in &active_features {
                    nfs.deactivate(&feature);
                }
                nfs.activate(&Pubkey::from_str("GaBtBJvmS4Arjj5W1NmFcyvPjsHN38UGYDq2MDwbs9Qu").unwrap(), 0);
                nfs.activate(&Pubkey::from_str("4RWNif6C2WCNiKVW7otP4G7dkmkHGyKQWRpuZ1pxKU5m").unwrap(), 0);
                nfs.activate(&Pubkey::from_str("DT4n6ABDqs6w4bnfwrXT9rsprcPf6cdDga1egctaPkLC").unwrap(), 0);
                nfs.activate(&Pubkey::from_str("BzBBveUDymEYoYzcMWNQCx3cd4jQs7puaVFHLtsbB6fm").unwrap(), 0);
                nfs.activate(&Pubkey::from_str("7XRJcS5Ud5vxGB54JbK9N2vBZVwnwdBNeJW1ibRgD9gx").unwrap(), 0);
                nfs.activate(&Pubkey::from_str("E3PHP7w8kB7np3CTQ1qQ2tW3KCtjRSXBQgW9vM2mWv2Y").unwrap(), 0);
                nfs.activate(&Pubkey::from_str("E5JiFDQCwyC6QfT9REFyMpfK2mHcmv1GUDySU1Ue7TYv").unwrap(), 0);
                nfs.activate(&Pubkey::from_str("4kpdyrcj5jS47CZb2oJGfVxjYbsMm2Kx97gFyZrxxwXz").unwrap(), 0);
                nfs.activate(&Pubkey::from_str("GE7fRxmW46K6EmCD9AMZSbnaJ2e3LfqCZzdHi9hmYAgi").unwrap(), 0);
                nfs.activate(&Pubkey::from_str("D4jsDcXaqdW8tDAWn8H4R25Cdns2YwLneujSL1zvjW6R").unwrap(), 0);
                nfs.activate(&Pubkey::from_str("BL99GYhdjjcv6ys22C9wPgn2aTVERDbPHHo4NbS3hgp7").unwrap(), 0);
                nfs.activate(&Pubkey::from_str("GvDsGDkH5gyzwpDhxNixx8vtx1kwYHH13RiNAPw27zXb").unwrap(), 0);
                nfs.activate(&Pubkey::from_str("3ccR6QpxGYsAbWyfevEtBNGfWV4xBffxRj2tD6A9i39F").unwrap(), 0);
                nfs.activate(&Pubkey::from_str("6RvdSWHh8oh72Dp7wMTS2DBkf3fRPtChfNrAo3cZZoXJ").unwrap(), 0);
                nfs.activate(&Pubkey::from_str("BrTR9hzw4WBGFP65AJMbpAo64DcA3U6jdPSga9fMV5cS").unwrap(), 0);
                nfs.activate(&Pubkey::from_str("HTW2pSyErTj4BV6KBM9NZ9VBUJVxt7sacNWcf76wtzb3").unwrap(), 0);
                nfs.activate(&Pubkey::from_str("8kEuAshXLsgkUEdcFVLqrjCGGHVWFW99ZZpxvAzzMtBp").unwrap(), 0);
                nfs.activate(&Pubkey::from_str("EVW9B5xD9FFK7vw1SBARwMA4s5eRo5eKJdKpsBikzKBz").unwrap(), 0);
                nfs.activate(&Pubkey::from_str("BcWknVcgvonN8sL4HE4XFuEVgfcee5MwxWPAgP6ZV89X").unwrap(), 0);
                nfs.activate(&Pubkey::from_str("BKCPBQQBZqggVnFso5nQ8rQ4RwwogYwjuUt9biBjxwNF").unwrap(), 0);
                nfs.activate(&Pubkey::from_str("DhsYfRjxfnh2g7HKJYSzT79r74Afa1wbHkAgHndrA1oy").unwrap(), 0);
                nfs.activate(&Pubkey::from_str("5ekBxc8itEnPv4NzGJtr8BVVQLNMQuLMNQQj7pHoLNZ9").unwrap(), 0);
                nfs.activate(&Pubkey::from_str("FToKNBYyiF4ky9s8WsmLBXHCht17Ek7RXaLZGHzzQhJ1").unwrap(), 0);
                nfs.activate(&Pubkey::from_str("21AWDosvp3pBamFW91KB35pNoaoZVTM7ess8nr2nt53B").unwrap(), 0);
                nfs.activate(&Pubkey::from_str("JAN1trEUEtZjgXYzNBYHU9DYd7GnThhXfFP7SzPXkPsG").unwrap(), 0);
                nfs.activate(&Pubkey::from_str("meRgp4ArRPhD3KtCY9c5yAf2med7mBLsjKTPeVUHqBL").unwrap(), 0);
                nfs.activate(&Pubkey::from_str("zk1snxsc6Fh3wsGNbbHAJNHiJoYgF29mMnTSusGx5EJ").unwrap(), 0);
                nfs.activate(&Pubkey::from_str("7rcw5UtqgDTBBv2EcynNfYckgdAaH1MAsCjKgXMkN7Ri").unwrap(), 0);
                nfs.activate(&Pubkey::from_str("3KZZ6Ks1885aGBQ45fwRcPXVBCtzUvxhUTkwKMR41Tca").unwrap(), 0);
                nfs.activate(&Pubkey::from_str("8aXvSuopd1PUj7UhehfXJRg6619RHp8ZvwTyyJHdUYsj").unwrap(), 0);
                nfs.activate(&Pubkey::from_str("54KAoNiUERNoWWUhTWWwXgym94gzoXFVnHyQwPA18V9A").unwrap(), 0);
                nfs.activate(&Pubkey::from_str("H3kBSaKdeiUsyHmeHqjJYNc27jesXZ6zWj3zWkowQbkV").unwrap(), 0);
                nfs.activate(&Pubkey::from_str("SAdVFw3RZvzbo6DvySbSdBnHN4gkzSTH9dSxesyKKPj").unwrap(), 0);
                nfs.activate(&Pubkey::from_str("BUS12ciZ5gCoFafUHWW8qaFMMtwFQGVxjsDheWLdqBE2").unwrap(), 0);
                nfs.activate(&Pubkey::from_str("3E3jV7v9VcdJL8iYZUMax9DiDno8j7EWUVbhm9RtShj2").unwrap(), 0);
                nfs.activate(&Pubkey::from_str("6ppMXNYLhVd7GcsZ5uV11wQEW7spppiMVfqQv5SXhDpX").unwrap(), 0);
                nfs.activate(&Pubkey::from_str("DwScAzPUjuv65TMbDnFY7AgwmotzWy3xpEJMXM3hZFaB").unwrap(), 0);
                nfs.activate(&Pubkey::from_str("EBeznQDjcPG8491sFsKZYBi5S5jTVXMpAKNDJMQPS2kq").unwrap(), 0);
                nfs.activate(&Pubkey::from_str("6uaHcKPGUy4J7emLBgUTeufhJdiwhngW6a1R9B7c2ob9").unwrap(), 0);
                nfs.activate(&Pubkey::from_str("HFpdDDNQjvcXnXKec697HDDsyk6tFoWS2o8fkxuhQZpL").unwrap(), 0);
                nfs.activate(&Pubkey::from_str("75m6ysz33AfLA5DDEzWM1obBrnPQRSsdVQ2nRmc8Vuu1").unwrap(), 0);
                nfs.activate(&Pubkey::from_str("4ApgRX3ud6p7LNMJmsuaAcZY5HWctGPr5obAsjB3A54d").unwrap(), 0);
                nfs.activate(&Pubkey::from_str("265hPS8k8xJ37ot82KEgjRunsUp5w4n4Q4VwwiN9i9ps").unwrap(), 0);
                nfs.activate(&Pubkey::from_str("HTTgmruMYRZEntyL3EdCDdnS6e4D5wRq1FA7kQsb66qq").unwrap(), 0);
                nfs.activate(&Pubkey::from_str("C5fh68nJ7uyKAuYZg2x9sEQ5YrVf3dkW6oojNBSc3Jvo").unwrap(), 0);
                nfs.activate(&Pubkey::from_str("CCu4boMmfLuqcmfTLPHQiUo22ZdUsXjgzPAURYaWt1Bw").unwrap(), 0);
                nfs.activate(&Pubkey::from_str("2jXx2yDmGysmBKfKYNgLj2DQyAQv6mMk2BPh4eSbyB4H").unwrap(), 0);
                nfs.activate(&Pubkey::from_str("4d5AKtxoh93Dwm1vHXUU3iRATuMndx1c431KgT2td52r").unwrap(), 0);
                nfs.activate(&Pubkey::from_str("BiCU7M5w8ZCMykVSyhZ7Q3m2SWoR2qrEQ86ERcDX77ME").unwrap(), 0);
                nfs.activate(&Pubkey::from_str("Ftok2jhqAqxUWEiCVRrfRs9DPppWP8cgTB7NQNKL88mS").unwrap(), 0);
                nfs.activate(&Pubkey::from_str("E8MkiWZNNPGU6n55jkGzyj8ghUmjCHRmDFdYYFYHxWhQ").unwrap(), 0);
                nfs.activate(&Pubkey::from_str("9kdtFSrXHQg3hKkbXkQ6trJ3Ja1xpJ22CTFSNAciEwmL").unwrap(), 0);
                nfs.activate(&Pubkey::from_str("36PRUK2Dz6HWYdG9SpjeAsF5F3KxnFCakA2BZMbtMhSb").unwrap(), 0);
                nfs.activate(&Pubkey::from_str("7txXZZD6Um59YoLMF7XUNimbMjsqsWhc7g2EniiTrmp1").unwrap(), 0);
                nfs.activate(&Pubkey::from_str("EMX9Q7TVFAmQ9V1CggAkhMzhXSg8ECp7fHrWQX2G1chf").unwrap(), 0);
                nfs.activate(&Pubkey::from_str("Ff8b1fBeB86q8cjq47ZhsQLgv5EkHu3G1C99zjUfAzrq").unwrap(), 0);
                nfs.activate(&Pubkey::from_str("capRxUrBjNkkCpjrJxPGfPaWijB7q3JoDfsWXAnt46r").unwrap(), 0);
                nfs.activate(&Pubkey::from_str("CBkDroRDqm8HwHe6ak9cguPjUomrASEkfmxEaZ5CNNxz").unwrap(), 0);
                nfs.activate(&Pubkey::from_str("BkFDxiJQWZXGTZaJQxH7wVEHkAmwCgSEVkrvswFfRJPD").unwrap(), 0);
                nfs.activate(&Pubkey::from_str("3gtZPqvPpsbXZVCx6hceMfWxtsmrjMzmg8C7PLKSxS2d").unwrap(), 0);
                nfs.activate(&Pubkey::from_str("2h63t332mGCCsWK2nqqqHhN4U9ayyqhLVFvczznHDoTZ").unwrap(), 0);
                nfs.activate(&Pubkey::from_str("437r62HoAdUb63amq3D7ENnBLDhHT2xY8eFkLJYVKK4x").unwrap(), 0);
                nfs.activate(&Pubkey::from_str("3EPmAX94PvVJCjMeFfRFvj4avqCPL8vv3TGsZQg7ydMx").unwrap(), 0);
                nfs.activate(&Pubkey::from_str("AVZS3ZsN4gi6Rkx2QUibYuSJG3S6QHib7xCYhG6vGJxU").unwrap(), 0);
                nfs.activate(&Pubkey::from_str("FaTa4SpiaSNH44PGC4z8bnGVTkSRYaWvrBs3KTu8XQQq").unwrap(), 0);
                nfs.activate(&Pubkey::from_str("ALBk3EWdeAg2WAGf6GPDUf1nynyNqCdEVmgouG7rpuCj").unwrap(), 0);
                nfs.activate(&Pubkey::from_str("CFK1hRCNy8JJuAAY8Pb2GjLFNdCThS2qwZNe3izzBMgn").unwrap(), 0);
                nfs.activate(&Pubkey::from_str("Vo5siZ442SaZBKPXNocthiXysNviW4UYPwRFggmbgAp").unwrap(), 0);
                nfs.activate(&Pubkey::from_str("3XgNukcZWf9o3HdA3fpJbm94XFc4qpvTXc8h1wxYwiPi").unwrap(), 0);
                nfs.activate(&Pubkey::from_str("4yuaYAj2jGMGTh1sSmi4G2eFscsDq8qjugJXZoBN6YEa").unwrap(), 0);
                nfs.activate(&Pubkey::from_str("3aJdcZqxoLpSBxgeYGjPwaYS1zzcByxUDqJkbzWAH1Zb").unwrap(), 0);
                nfs.activate(&Pubkey::from_str("HyrbKftCdJ5CrUfEti6x26Cj7rZLNe32weugk7tLcWb8").unwrap(), 0);
                nfs.activate(&Pubkey::from_str("nWBqjr3gpETbiaVj3CBJ3HFC5TMdnJDGt21hnvSTvVZ").unwrap(), 0);
                nfs.activate(&Pubkey::from_str("7g9EUwj4j7CS21Yx1wvgWLjSZeh5aPq8x9kpoPwXM8n8").unwrap(), 0);
                nfs.activate(&Pubkey::from_str("GTUMCZ8LTNxVfxdrw7ZsDFTxXb7TutYkzJnFwinpE6dg").unwrap(), 0);
                nfs.activate(&Pubkey::from_str("GmC19j9qLn2RFk5NduX6QXaDhVpGncVVBzyM8e9WMz2F").unwrap(), 0);
                nfs.activate(&Pubkey::from_str("FQnc7U4koHqWgRvFaBJjZnV8VPg6L6wWK33yJeDp4yvV").unwrap(), 0);
                nfs.activate(&Pubkey::from_str("St8k9dVXP97xT6faW24YmRSYConLbhsMJA4TJTBLmMT").unwrap(), 0);
                nfs.activate(&Pubkey::from_str("8199Q2gMD2kwgfopK5qqVWuDbegLgpuFUFHCcUJQDN8b").unwrap(), 0);
                nfs.activate(&Pubkey::from_str("3NKRSwpySNwD3TvP5pHnRmkAQRsdkXWRr1WaQh8p4PWX").unwrap(), 0);
                nfs.activate(&Pubkey::from_str("4Di3y24QFLt5QEUPZtbnjyfQKfm6ZMTfa6Dw1psfoMKU").unwrap(), 0);
                nfs.activate(&Pubkey::from_str("7GUcYgq4tVtaqNCKT3dho9r4665Qp5TxCZ27Qgjx3829").unwrap(), 0);
                nfs.activate(&Pubkey::from_str("6iyggb5MTcsvdcugX7bEKbHV8c6jdLbpHwkncrgLMhfo").unwrap(), 0);
                nfs.activate(&Pubkey::from_str("28s7i3htzhahXQKqmS2ExzbEoUypg9krwvtK2M9UWXh9").unwrap(), 0);
                nfs.activate(&Pubkey::from_str("HCnE3xQoZtDz9dSVm3jKwJXioTb6zMRbgwCmGg3PHHk8").unwrap(), 0);
                nfs.activate(&Pubkey::from_str("Ftok4njE8b7tDffYkC5bAbCaQv5sL6jispYrprzatUwN").unwrap(), 0);
                nfs.activate(&Pubkey::from_str("FaTa17gVKoqbh38HcfiQonPsAaQViyDCCSg71AubYZw8").unwrap(), 0);
                nfs.activate(&Pubkey::from_str("J2QdYx8crLbTVK8nur1jeLsmc3krDbfjoxoea2V1Uy5Q").unwrap(), 0);
                nfs.activate(&Pubkey::from_str("sTKz343FM8mqtyGvYWvbLpTThw3ixRM4Xk8QvZ985mw").unwrap(), 0);
                nfs.activate(&Pubkey::from_str("8FdwgyHFEjhAdjWfV2vfqk7wA1g9X3fQpKH7SBpEv3kC").unwrap(), 0);
                nfs.activate(&Pubkey::from_str("9onWzzvCzNC2jfhxxeqRgs5q7nFAAKpCUvkj6T6GJK9i").unwrap(), 0);
                nfs.activate(&Pubkey::from_str("ELjxSXwNsyXGfAh8TqX8ih22xeT8huF6UngQirbLKYKH").unwrap(), 0);
                nfs.activate(&Pubkey::from_str("98std1NSHqXi9WYvFShfVepRdCoq1qvsp8fsR2XZtG8g").unwrap(), 0);
                nfs.activate(&Pubkey::from_str("79HWsX9rpnnJBPcdNURVqygpMAfxdrAirzAGAVmf92im").unwrap(), 0);
                nfs.activate(&Pubkey::from_str("2R72wpcQ7qV7aTJWUumdn8u5wmmTyXbK7qzEy7YSAgyY").unwrap(), 0);
                nfs.activate(&Pubkey::from_str("Ds87KVeqhbv7Jw8W6avsS1mqz3Mw5J3pRTpPoDQ2QdiJ").unwrap(), 0);
                nfs.activate(&Pubkey::from_str("3BX6SBeEBibHaVQXywdkcgyUk6evfYZkHdztXiDtEpFS").unwrap(), 0);
                nfs.activate(&Pubkey::from_str("Gea3ZkK2N4pHuVZVxWcnAtS6UEDdyumdYt4pFcKjA3ar").unwrap(), 0);
                nfs.activate(&Pubkey::from_str("4EJQtF2pkRyawwcTVfQutzq4Sa5hRhibF6QAK1QXhtEX").unwrap(), 0);
                nfs.activate(&Pubkey::from_str("CveezY6FDLVBToHDcvJRmtMouqzsmj4UXYh5ths5G5Uv").unwrap(), 0);
                nfs.activate(&Pubkey::from_str("DpJREPyuMZ5nDfU6H3WTqSqUFSXAfw8u7xqmWtEwJDcP").unwrap(), 0);
                nfs.activate(&Pubkey::from_str("HxrEu1gXuH7iD3Puua1ohd5n4iUKJyFNtNxk9DVJkvgr").unwrap(), 0);
                nfs.activate(&Pubkey::from_str("3u3Er5Vc2jVcwz4xr2GJeSAXT3fAj6ADHZ4BJMZiScFd").unwrap(), 0);
                nfs.activate(&Pubkey::from_str("6tRxEYKuy2L5nnv5bgn7iT28MxUbYxp5h7F3Ncf1exrT").unwrap(), 0);
                nfs.activate(&Pubkey::from_str("qywiJyZmqTKspFg2LeuUHqcA5nNvBgobqb9UprywS9N").unwrap(), 0);
                nfs.activate(&Pubkey::from_str("HH3MUYReL2BvqqA3oEcAa7txju5GY6G4nxJ51zvsEjEZ").unwrap(), 0);
                nfs.activate(&Pubkey::from_str("8Zs9W7D9MpSEtUWSQdGniZk2cNmV22y6FLJwCx53asme").unwrap(), 0);
                nfs.activate(&Pubkey::from_str("7Vced912WrRnfjaiKRiNBcbuFw7RrnLv3E3z95Y4GTNc").unwrap(), 0);
                nfs.activate(&Pubkey::from_str("CGB2jM8pwZkeeiXQ66kBMyBR6Np61mggL7XUsmLjVcrw").unwrap(), 0);
                nfs.activate(&Pubkey::from_str("812kqX67odAp5NFwM8D2N24cku7WTm9CHUTFUXaDkWPn").unwrap(), 0);
                nfs.activate(&Pubkey::from_str("9k5ijzTbYPtjzu8wj2ErH9v45xecHzQ1x4PMYMMxFgdM").unwrap(), 0);
                nfs.activate(&Pubkey::from_str("GDH5TVdbTPUpRnXaRyQqiKUa7uZAbZ28Q2N9bhbKoMLm").unwrap(), 0);
                nfs.activate(&Pubkey::from_str("8sKQrMQoUHtQSUP83SPG4ta2JDjSAiWs7t5aJ9uEd6To").unwrap(), 0);
                nfs.activate(&Pubkey::from_str("86HpNqzutEZwLcPxS6EHDcMNYWk6ikhteg9un7Y2PBKE").unwrap(), 0);
                nfs.activate(&Pubkey::from_str("25vqsfjk7Nv1prsQJmA4Xu1bN61s8LXCBGUPp8Rfy1UF").unwrap(), 0);
                nfs.activate(&Pubkey::from_str("B9cdB55u4jQsDNsdTK525yE9dmSc5Ga7YBaBrDFvEhM9").unwrap(), 0);
                nfs.activate(&Pubkey::from_str("CpkdQmspsaZZ8FVAouQTtTWZkc8eeQ7V3uj7dWz543rZ").unwrap(), 0);
                nfs.activate(&Pubkey::from_str("SVn36yVApPLYsa8koK3qUcy14zXDnqkNYWyUh1f4oK1").unwrap(), 0);
                nfs.activate(&Pubkey::from_str("5wAGiy15X1Jb2hkHnPDCM8oB9V42VNA9ftNVFK84dEgv").unwrap(), 0);
                nfs.activate(&Pubkey::from_str("FKAcEvNgSY79RpqsPNUV5gDyumopH4cEHqUxyfm8b8Ap").unwrap(), 0);
                nfs.activate(&Pubkey::from_str("EYVpEP7uzH1CoXzbD6PubGhYmnxRXPeq3PPsm1ba3gpo").unwrap(), 0);
                nfs.activate(&Pubkey::from_str("G74BkWBzmsByZ1kxHy44H3wjwp5hp7JbrGRuDpco22tY").unwrap(), 0);
                nfs.activate(&Pubkey::from_str("9gxu85LYRAcZL38We8MYJ4A9AwgBBPtVBAqebMcT1241").unwrap(), 0);
                nfs.activate(&Pubkey::from_str("5GpmAKxaGsWWbPp4bNXFLJxZVvG92ctxf7jQnzTQjF3n").unwrap(), 0);
                nfs.activate(&Pubkey::from_str("EfhYd3SafzGT472tYQDUc4dPd2xdEfKs5fwkowUgVt4W").unwrap(), 0);
                nfs.activate(&Pubkey::from_str("DTVTkmw3JSofd8CJVJte8PXEbxNQ2yZijvVr3pe2APPj").unwrap(), 0);
                nfs.activate(&Pubkey::from_str("9LZdXeKGeBV6hRLdxS1rHbHoEUsKqesCC2ZAPTPKJAbK").unwrap(), 0);
                nfs.activate(&Pubkey::from_str("GQALDaC48fEhZGWRj9iL5Q889emJKcj3aCvHF7VCbbF4").unwrap(), 0);
                nfs.activate(&Pubkey::from_str("3uRVPBpyEJRo1emLCrq38eLRFGcu6uKSpUXqGvU8T7SZ").unwrap(), 0);
                nfs.activate(&Pubkey::from_str("5x3825XS7M2A3Ekbn5VGGkvFoAg5qrRWkTrY4bARP1GL").unwrap(), 0);
                nfs.activate(&Pubkey::from_str("A16q37opZdQMCbe5qJ6xpBB9usykfv8jZaMkxvZQi4GJ").unwrap(), 0);
                nfs.activate(&Pubkey::from_str("J4HFT8usBxpcF63y46t1upYobJgChmKyZPm5uTBRg25Z").unwrap(), 0);
                nfs.activate(&Pubkey::from_str("noRuG2kzACwgaY7TVmLRnUNPLKNVQE1fb7X55YWBehp").unwrap(), 0);
                nfs.activate(&Pubkey::from_str("D31EFnLgdiysi84Woo3of4JMu7VmasUS3Z7j9HYXCeLY").unwrap(), 0);
                nfs.activate(&Pubkey::from_str("Gz1aLrbeQ4Q6PTSafCZcGWZXz91yVRi7ASFzFEr1U4sa").unwrap(), 0);
                nfs.activate(&Pubkey::from_str("84zy5N23Q9vTZuLc9h1HWUtyM9yCFV2SCmyP9W9C3yHZ").unwrap(), 0);
                nfs.activate(&Pubkey::from_str("HyNQzc7TMNmRhpVHXqDGjpsHzeQie82mDQXSF9hj7nAH").unwrap(), 0);
                nfs.activate(&Pubkey::from_str("74CoWuBmt3rUVUrCb2JiSTvh6nXyBWUsK4SaMj3CtE3T").unwrap(), 0);
                nfs.activate(&Pubkey::from_str("3uFHb9oKdGfgZGJK9EHaAXN4USvnQtAFC13Fh5gGFS5B").unwrap(), 0);
                nfs.activate(&Pubkey::from_str("EBq48m8irRKuE7ZnMTLvLg2UuGSqhe8s8oMqnmja1fJw").unwrap(), 0);
                nfs.activate(&Pubkey::from_str("4UDcAfQ6EcA6bdcadkeHpkarkhZGJ7Bpq7wTAiRMjkoi").unwrap(), 0);
                nfs.activate(&Pubkey::from_str("DdLwVYuvDz26JohmgSbA7mjpJFgX5zP2dkp8qsF2C33V").unwrap(), 0);
                nfs.activate(&Pubkey::from_str("A8xyMHZovGXFkorFqEmVH2PKGLiBip5JD7jt4zsUWo4H").unwrap(), 0);
                nfs.activate(&Pubkey::from_str("Hr1nUA9b7NJ6eChS26o7Vi8gYYDDwWD3YeBfzJkTbU86").unwrap(), 0);
                nfs.activate(&Pubkey::from_str("Fab5oP3DmsLYCiQZXdjyqT3ukFFPrsmqhXU4WU1AWVVF").unwrap(), 0);
                nfs.activate(&Pubkey::from_str("GmuBvtFb2aHfSfMXpuFeWZGHyDeCLPS79s48fmCWCfM5").unwrap(), 0);
                nfs.activate(&Pubkey::from_str("2ry7ygxiYURULZCrypHhveanvP5tzZ4toRwVp89oCNSj").unwrap(), 0);
                nfs.activate(&Pubkey::from_str("9gwzizfABsKUereT6phZZxbTzuAnovkgwpVVpdcSxv9h").unwrap(), 0);
                nfs.activate(&Pubkey::from_str("G6vbf1UBok8MWb8m25ex86aoQHeKTzDKzuZADHkShqm6").unwrap(), 0);
                nfs.activate(&Pubkey::from_str("Cdkc8PPTeTNUPoZEfCY5AyetUrEdkZtNPMgz58nqyaHD").unwrap(), 0);
                nfs.activate(&Pubkey::from_str("CE2et8pqgyQMP2mQRg3CgvX8nJBKUArMu3wfiQiQKY1y").unwrap(), 0);
                nfs.activate(&Pubkey::from_str("2HmTkCj9tXuPE4ueHzdD7jPeMf9JGCoZh5AsyoATiWEe").unwrap(), 0);
                nfs.activate(&Pubkey::from_str("EaQpmC6GtRssaZ3PCUM5YksGqUdMLeZ46BQXYtHYakDS").unwrap(), 0);
                nfs.activate(&Pubkey::from_str("8pgXCMNXC8qyEFypuwpXyRxLXZdpM4Qo72gJ6k87A6wL").unwrap(), 0);
                nfs.activate(&Pubkey::from_str("5ZCcFAzJ1zsFKe1KSZa9K92jhx7gkcKj97ci2DBo1vwj").unwrap(), 0);
                nfs.activate(&Pubkey::from_str("16FMCmgLzCNNz6eTwGanbyN2ZxvTBSLuQ6DZhgeMshg").unwrap(), 0);
                nfs.activate(&Pubkey::from_str("Bj2jmUsM2iRhfdLLDSTkhM5UQRQvQHm57HSmPibPtEyu").unwrap(), 0);
                nfs.activate(&Pubkey::from_str("7axKe5BTYBDD87ftzWbk5DfzWMGyRvqmWTduuo22Yaqy").unwrap(), 0);
                nfs.activate(&Pubkey::from_str("5Pecy6ie6XGm22pc9d4P9W5c31BugcFBuy6hsP2zkETv").unwrap(), 0);
                nfs.activate(&Pubkey::from_str("HooKD5NC9QNxk25QuzCssB8ecrEzGt6eXEPBUxWp1LaR").unwrap(), 0);
                nfs.activate(&Pubkey::from_str("GwtDQBghCTBgmX2cpEGNPxTEBUTQRaDMGTr5qychdGMj").unwrap(), 0);
            },
            None => {},
        }
    }

    let fs = (&serde_json::to_string(&invoke_context.feature_set.inactive).unwrap()).to_string();

    let result = invoke_context.process_instruction(
        instruction_data,
        &instruction_accounts,
        &program_indices,
        &mut 0,
        &mut ExecuteTimings::default(),
    );
    if mainnet  {
        expected_result = result;
    } else {
        assert_eq!(result, expected_result);
    }
    post_adjustments(&mut invoke_context);
    let mut transaction_accounts = transaction_context.deconstruct_without_keys().unwrap();
    transaction_accounts.pop();

    let bts = Backtrace::capture().to_string();

    println!("test_case_json {}", serde_json::to_string(&TestCase {
        name: std::thread::current().name().unwrap().to_string(),
        program_id: loader_id.clone(),
        backtrace: bts,
        feature_set: fs,
        sysvar_cache: tsvc,
        instruction_data: Vec::from(instruction_data),
        transaction_accounts: before,
        resulting_accounts: transaction_accounts.clone().into_iter().map(|shared_data| {
            TestAccountSharedData { lamports: shared_data.lamports(), data: shared_data.data().to_vec(), owner: *shared_data.owner(), executable: shared_data.executable(), rent_epoch: shared_data.rent_epoch() }
        }).collect(),
        instruction_accounts: instruction_accounts.clone().into_iter().map(|acc_meta| {
            TestInstructionAccount {
                index_in_transaction: acc_meta.index_in_transaction,
                index_in_caller: acc_meta.index_in_caller,
                index_in_callee: acc_meta.index_in_callee,
                is_signer: acc_meta.is_signer,
                is_writable: acc_meta.is_writable }
        }).collect(),
        expected_result: expected_result.clone(),
    }).unwrap());

    transaction_accounts
}

#[cfg(test)]
mod tests {
    use {
        super::*,
        crate::compute_budget,
        serde::{Deserialize, Serialize},
        solana_sdk::{account::WritableAccount, instruction::Instruction},
    };

    #[derive(Debug, Serialize, Deserialize)]
    enum MockInstruction {
        NoopSuccess,
        NoopFail,
        ModifyOwned,
        ModifyNotOwned,
        ModifyReadonly,
        UnbalancedPush,
        UnbalancedPop,
        ConsumeComputeUnits {
            compute_units_to_consume: u64,
            desired_result: Result<(), InstructionError>,
        },
        Resize {
            new_len: u64,
        },
    }

    const MOCK_BUILTIN_COMPUTE_UNIT_COST: u64 = 1;

    declare_process_instruction!(
        process_instruction,
        MOCK_BUILTIN_COMPUTE_UNIT_COST,
        |invoke_context| {
            let transaction_context = &invoke_context.transaction_context;
            let instruction_context = transaction_context.get_current_instruction_context()?;
            let instruction_data = instruction_context.get_instruction_data();
            let program_id = instruction_context.get_last_program_key(transaction_context)?;
            let instruction_accounts = (0..4)
                .map(|instruction_account_index| InstructionAccount {
                    index_in_transaction: instruction_account_index,
                    index_in_caller: instruction_account_index,
                    index_in_callee: instruction_account_index,
                    is_signer: false,
                    is_writable: false,
                })
                .collect::<Vec<_>>();
            assert_eq!(
                program_id,
                instruction_context
                    .try_borrow_instruction_account(transaction_context, 0)?
                    .get_owner()
            );
            assert_ne!(
                instruction_context
                    .try_borrow_instruction_account(transaction_context, 1)?
                    .get_owner(),
                instruction_context
                    .try_borrow_instruction_account(transaction_context, 0)?
                    .get_key()
            );

            if let Ok(instruction) = bincode::deserialize(instruction_data) {
                match instruction {
                    MockInstruction::NoopSuccess => (),
                    MockInstruction::NoopFail => return Err(InstructionError::GenericError),
                    MockInstruction::ModifyOwned => instruction_context
                        .try_borrow_instruction_account(transaction_context, 0)?
                        .set_data_from_slice(&[1])?,
                    MockInstruction::ModifyNotOwned => instruction_context
                        .try_borrow_instruction_account(transaction_context, 1)?
                        .set_data_from_slice(&[1])?,
                    MockInstruction::ModifyReadonly => instruction_context
                        .try_borrow_instruction_account(transaction_context, 2)?
                        .set_data_from_slice(&[1])?,
                    MockInstruction::UnbalancedPush => {
                        instruction_context
                            .try_borrow_instruction_account(transaction_context, 0)?
                            .checked_add_lamports(1)?;
                        let program_id = *transaction_context.get_key_of_account_at_index(3)?;
                        let metas = vec![
                            AccountMeta::new_readonly(
                                *transaction_context.get_key_of_account_at_index(0)?,
                                false,
                            ),
                            AccountMeta::new_readonly(
                                *transaction_context.get_key_of_account_at_index(1)?,
                                false,
                            ),
                        ];
                        let inner_instruction = Instruction::new_with_bincode(
                            program_id,
                            &MockInstruction::NoopSuccess,
                            metas,
                        );
                        invoke_context
                            .transaction_context
                            .get_next_instruction_context()
                            .unwrap()
                            .configure(&[3], &instruction_accounts, &[]);
                        let result = invoke_context.push();
                        assert_eq!(result, Err(InstructionError::UnbalancedInstruction));
                        result?;
                        invoke_context
                            .native_invoke(inner_instruction.into(), &[])
                            .and(invoke_context.pop())?;
                    }
                    MockInstruction::UnbalancedPop => instruction_context
                        .try_borrow_instruction_account(transaction_context, 0)?
                        .checked_add_lamports(1)?,
                    MockInstruction::ConsumeComputeUnits {
                        compute_units_to_consume,
                        desired_result,
                    } => {
                        invoke_context
                            .consume_checked(compute_units_to_consume)
                            .map_err(|_| InstructionError::ComputationalBudgetExceeded)?;
                        return desired_result;
                    }
                    MockInstruction::Resize { new_len } => instruction_context
                        .try_borrow_instruction_account(transaction_context, 0)?
                        .set_data(vec![0; new_len as usize])?,
                }
            } else {
                return Err(InstructionError::InvalidInstructionData);
            }
            Ok(())
        }
    );

    #[test]
    fn test_instruction_stack_height() {
        let one_more_than_max_depth = ComputeBudget::default()
            .max_invoke_stack_height
            .saturating_add(1);
        let mut invoke_stack = vec![];
        let mut transaction_accounts = vec![];
        let mut instruction_accounts = vec![];
        for index in 0..one_more_than_max_depth {
            invoke_stack.push(solana_sdk::pubkey::new_rand());
            transaction_accounts.push((
                solana_sdk::pubkey::new_rand(),
                AccountSharedData::new(index as u64, 1, invoke_stack.get(index).unwrap()),
            ));
            instruction_accounts.push(InstructionAccount {
                index_in_transaction: index as IndexOfAccount,
                index_in_caller: index as IndexOfAccount,
                index_in_callee: instruction_accounts.len() as IndexOfAccount,
                is_signer: false,
                is_writable: true,
            });
        }
        for (index, program_id) in invoke_stack.iter().enumerate() {
            transaction_accounts.push((
                *program_id,
                AccountSharedData::new(1, 1, &solana_sdk::pubkey::Pubkey::default()),
            ));
            instruction_accounts.push(InstructionAccount {
                index_in_transaction: index as IndexOfAccount,
                index_in_caller: index as IndexOfAccount,
                index_in_callee: index as IndexOfAccount,
                is_signer: false,
                is_writable: false,
            });
        }
        with_mock_invoke_context!(invoke_context, transaction_context, transaction_accounts);

        // Check call depth increases and has a limit
        let mut depth_reached = 0;
        for _ in 0..invoke_stack.len() {
            invoke_context
                .transaction_context
                .get_next_instruction_context()
                .unwrap()
                .configure(
                    &[one_more_than_max_depth.saturating_add(depth_reached) as IndexOfAccount],
                    &instruction_accounts,
                    &[],
                );
            if Err(InstructionError::CallDepth) == invoke_context.push() {
                break;
            }
            depth_reached = depth_reached.saturating_add(1);
        }
        assert_ne!(depth_reached, 0);
        assert!(depth_reached < one_more_than_max_depth);
    }

    #[test]
    fn test_max_instruction_trace_length() {
        const MAX_INSTRUCTIONS: usize = 8;
        let mut transaction_context =
            TransactionContext::new(Vec::new(), Some(Rent::default()), 1, MAX_INSTRUCTIONS);
        for _ in 0..MAX_INSTRUCTIONS {
            transaction_context.push().unwrap();
            transaction_context.pop().unwrap();
        }
        assert_eq!(
            transaction_context.push(),
            Err(InstructionError::MaxInstructionTraceLengthExceeded)
        );
    }

    #[test]
    fn test_process_instruction() {
        let callee_program_id = solana_sdk::pubkey::new_rand();
        let owned_account = AccountSharedData::new(42, 1, &callee_program_id);
        let not_owned_account = AccountSharedData::new(84, 1, &solana_sdk::pubkey::new_rand());
        let readonly_account = AccountSharedData::new(168, 1, &solana_sdk::pubkey::new_rand());
        let loader_account = AccountSharedData::new(0, 0, &native_loader::id());
        let mut program_account = AccountSharedData::new(1, 0, &native_loader::id());
        program_account.set_executable(true);
        let transaction_accounts = vec![
            (solana_sdk::pubkey::new_rand(), owned_account),
            (solana_sdk::pubkey::new_rand(), not_owned_account),
            (solana_sdk::pubkey::new_rand(), readonly_account),
            (callee_program_id, program_account),
            (solana_sdk::pubkey::new_rand(), loader_account),
        ];
        let metas = vec![
            AccountMeta::new(transaction_accounts.get(0).unwrap().0, false),
            AccountMeta::new(transaction_accounts.get(1).unwrap().0, false),
            AccountMeta::new_readonly(transaction_accounts.get(2).unwrap().0, false),
        ];
        let instruction_accounts = (0..4)
            .map(|instruction_account_index| InstructionAccount {
                index_in_transaction: instruction_account_index,
                index_in_caller: instruction_account_index,
                index_in_callee: instruction_account_index,
                is_signer: false,
                is_writable: instruction_account_index < 2,
            })
            .collect::<Vec<_>>();
        with_mock_invoke_context!(invoke_context, transaction_context, transaction_accounts);
        let mut programs_loaded_for_tx_batch = LoadedProgramsForTxBatch::default();
        programs_loaded_for_tx_batch.replenish(
            callee_program_id,
            Arc::new(LoadedProgram::new_builtin(0, 0, process_instruction)),
        );
        invoke_context.programs_loaded_for_tx_batch = &programs_loaded_for_tx_batch;

        // Account modification tests
        let cases = vec![
            (MockInstruction::NoopSuccess, Ok(())),
            (
                MockInstruction::NoopFail,
                Err(InstructionError::GenericError),
            ),
            (MockInstruction::ModifyOwned, Ok(())),
            (
                MockInstruction::ModifyNotOwned,
                Err(InstructionError::ExternalAccountDataModified),
            ),
            (
                MockInstruction::ModifyReadonly,
                Err(InstructionError::ReadonlyDataModified),
            ),
            (
                MockInstruction::UnbalancedPush,
                Err(InstructionError::UnbalancedInstruction),
            ),
            (
                MockInstruction::UnbalancedPop,
                Err(InstructionError::UnbalancedInstruction),
            ),
        ];
        for case in cases {
            invoke_context
                .transaction_context
                .get_next_instruction_context()
                .unwrap()
                .configure(&[4], &instruction_accounts, &[]);
            invoke_context.push().unwrap();
            let inner_instruction =
                Instruction::new_with_bincode(callee_program_id, &case.0, metas.clone());
            let result = invoke_context
                .native_invoke(inner_instruction.into(), &[])
                .and(invoke_context.pop());
            assert_eq!(result, case.1);
        }

        // Compute unit consumption tests
        let compute_units_to_consume = 10;
        let expected_results = vec![Ok(()), Err(InstructionError::GenericError)];
        for expected_result in expected_results {
            invoke_context
                .transaction_context
                .get_next_instruction_context()
                .unwrap()
                .configure(&[4], &instruction_accounts, &[]);
            invoke_context.push().unwrap();
            let inner_instruction = Instruction::new_with_bincode(
                callee_program_id,
                &MockInstruction::ConsumeComputeUnits {
                    compute_units_to_consume,
                    desired_result: expected_result.clone(),
                },
                metas.clone(),
            );
            let inner_instruction = StableInstruction::from(inner_instruction);
            let (inner_instruction_accounts, program_indices) = invoke_context
                .prepare_instruction(&inner_instruction, &[])
                .unwrap();

            let mut compute_units_consumed = 0;
            let result = invoke_context.process_instruction(
                &inner_instruction.data,
                &inner_instruction_accounts,
                &program_indices,
                &mut compute_units_consumed,
                &mut ExecuteTimings::default(),
            );

            // Because the instruction had compute cost > 0, then regardless of the execution result,
            // the number of compute units consumed should be a non-default which is something greater
            // than zero.
            assert!(compute_units_consumed > 0);
            assert_eq!(
                compute_units_consumed,
                compute_units_to_consume.saturating_add(MOCK_BUILTIN_COMPUTE_UNIT_COST),
            );
            assert_eq!(result, expected_result);

            invoke_context.pop().unwrap();
        }
    }

    #[test]
    fn test_invoke_context_compute_budget() {
        let transaction_accounts =
            vec![(solana_sdk::pubkey::new_rand(), AccountSharedData::default())];

        with_mock_invoke_context!(invoke_context, transaction_context, transaction_accounts);
        invoke_context.compute_budget =
            ComputeBudget::new(compute_budget::DEFAULT_INSTRUCTION_COMPUTE_UNIT_LIMIT as u64);

        invoke_context
            .transaction_context
            .get_next_instruction_context()
            .unwrap()
            .configure(&[0], &[], &[]);
        invoke_context.push().unwrap();
        assert_eq!(
            *invoke_context.get_compute_budget(),
            ComputeBudget::new(compute_budget::DEFAULT_INSTRUCTION_COMPUTE_UNIT_LIMIT as u64)
        );
        invoke_context.pop().unwrap();
    }

    #[test]
    fn test_process_instruction_accounts_resize_delta() {
        let program_key = Pubkey::new_unique();
        let user_account_data_len = 123u64;
        let user_account =
            AccountSharedData::new(100, user_account_data_len as usize, &program_key);
        let dummy_account = AccountSharedData::new(10, 0, &program_key);
        let mut program_account = AccountSharedData::new(500, 500, &native_loader::id());
        program_account.set_executable(true);
        let transaction_accounts = vec![
            (Pubkey::new_unique(), user_account),
            (Pubkey::new_unique(), dummy_account),
            (program_key, program_account),
        ];
        let instruction_accounts = [
            InstructionAccount {
                index_in_transaction: 0,
                index_in_caller: 0,
                index_in_callee: 0,
                is_signer: false,
                is_writable: true,
            },
            InstructionAccount {
                index_in_transaction: 1,
                index_in_caller: 1,
                index_in_callee: 1,
                is_signer: false,
                is_writable: false,
            },
        ];
        with_mock_invoke_context!(invoke_context, transaction_context, transaction_accounts);
        let mut programs_loaded_for_tx_batch = LoadedProgramsForTxBatch::default();
        programs_loaded_for_tx_batch.replenish(
            program_key,
            Arc::new(LoadedProgram::new_builtin(0, 0, process_instruction)),
        );
        invoke_context.programs_loaded_for_tx_batch = &programs_loaded_for_tx_batch;

        // Test: Resize the account to *the same size*, so not consuming any additional size; this must succeed
        {
            let resize_delta: i64 = 0;
            let new_len = (user_account_data_len as i64).saturating_add(resize_delta) as u64;
            let instruction_data =
                bincode::serialize(&MockInstruction::Resize { new_len }).unwrap();

            let result = invoke_context.process_instruction(
                &instruction_data,
                &instruction_accounts,
                &[2],
                &mut 0,
                &mut ExecuteTimings::default(),
            );

            assert!(result.is_ok());
            assert_eq!(
                invoke_context
                    .transaction_context
                    .accounts_resize_delta()
                    .unwrap(),
                resize_delta
            );
        }

        // Test: Resize the account larger; this must succeed
        {
            let resize_delta: i64 = 1;
            let new_len = (user_account_data_len as i64).saturating_add(resize_delta) as u64;
            let instruction_data =
                bincode::serialize(&MockInstruction::Resize { new_len }).unwrap();

            let result = invoke_context.process_instruction(
                &instruction_data,
                &instruction_accounts,
                &[2],
                &mut 0,
                &mut ExecuteTimings::default(),
            );

            assert!(result.is_ok());
            assert_eq!(
                invoke_context
                    .transaction_context
                    .accounts_resize_delta()
                    .unwrap(),
                resize_delta
            );
        }

        // Test: Resize the account smaller; this must succeed
        {
            let resize_delta: i64 = -1;
            let new_len = (user_account_data_len as i64).saturating_add(resize_delta) as u64;
            let instruction_data =
                bincode::serialize(&MockInstruction::Resize { new_len }).unwrap();

            let result = invoke_context.process_instruction(
                &instruction_data,
                &instruction_accounts,
                &[2],
                &mut 0,
                &mut ExecuteTimings::default(),
            );

            assert!(result.is_ok());
            assert_eq!(
                invoke_context
                    .transaction_context
                    .accounts_resize_delta()
                    .unwrap(),
                resize_delta
            );
        }
    }
}

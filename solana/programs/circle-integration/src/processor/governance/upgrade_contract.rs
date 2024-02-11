use crate::{
    constants::UPGRADE_SEED_PREFIX,
    error::CircleIntegrationError,
    state::{ConsumedVaa, Custodian},
};
use anchor_lang::prelude::*;
use wormhole_cctp_solana::wormhole::{core_bridge_program, VaaAccount, SOLANA_CHAIN};
use wormhole_solana_utils::cpi::bpf_loader_upgradeable::{self, BpfLoaderUpgradeable};

#[derive(Accounts)]
pub struct UpgradeContract<'info> {
    #[account(mut)]
    payer: Signer<'info>,

    #[account(
        seeds = [Custodian::SEED_PREFIX],
        bump = custodian.bump,
    )]
    custodian: Account<'info, Custodian>,

    /// CHECK: Posted VAA account, which will be read via zero-copy deserialization in the
    /// instruction handler, which also checks this account discriminator (so there is no need to
    /// check PDA seeds here).
    #[account(owner = core_bridge_program::id())]
    vaa: AccountInfo<'info>,

    #[account(
        init,
        payer = payer,
        space = 8 + ConsumedVaa::INIT_SPACE,
        seeds = [
            ConsumedVaa::SEED_PREFIX,
            VaaAccount::load(&vaa)?.digest().as_ref(),
        ],
        bump,
    )]
    consumed_vaa: Account<'info, ConsumedVaa>,

    /// CHECK: We need this upgrade authority to invoke the BPF Loader Upgradeable program to
    /// upgrade this program's executable. We verify this PDA address here out of convenience to get
    /// the PDA bump seed to invoke the upgrade.
    #[account(
        seeds = [UPGRADE_SEED_PREFIX],
        bump = custodian.upgrade_authority_bump,
    )]
    upgrade_authority: AccountInfo<'info>,

    /// CHECK: This account receives any lamports after the result of the upgrade.
    #[account(mut)]
    spill: AccountInfo<'info>,

    /// CHECK: Deployed implementation. The pubkey of this account is checked in access control
    /// against the one encoded in the governance VAA.
    #[account(mut)]
    buffer: AccountInfo<'info>,

    /// CHECK: Token Bridge program data needed for BPF Loader Upgradable program.
    #[account(
        mut,
        seeds = [crate::ID.as_ref()],
        bump,
        seeds::program = bpf_loader_upgradeable::id(),
    )]
    program_data: AccountInfo<'info>,

    /// CHECK: This must equal the Token Bridge program ID for the BPF Loader Upgradeable program.
    #[account(
        mut,
        address = crate::ID
    )]
    this_program: AccountInfo<'info>,

    /// CHECK: BPF Loader Upgradeable program needs this sysvar.
    #[account(address = solana_program::sysvar::rent::id())]
    rent: AccountInfo<'info>,

    /// CHECK: BPF Loader Upgradeable program needs this sysvar.
    #[account(address = solana_program::sysvar::clock::id())]
    clock: AccountInfo<'info>,

    /// CHECK: BPF Loader Upgradeable program.
    bpf_loader_upgradeable_program: Program<'info, BpfLoaderUpgradeable>,

    system_program: Program<'info, System>,
}

/// Processor for contract upgrade governance decrees. This instruction handler invokes the BPF
/// Loader Upgradeable program to upgrade this program's executable to the provided buffer.
#[access_control(handle_access_control(&ctx))]
pub fn upgrade_contract(ctx: Context<UpgradeContract>) -> Result<()> {
    ctx.accounts.consumed_vaa.set_inner(ConsumedVaa {
        bump: ctx.bumps.consumed_vaa,
    });

    // Finally upgrade.
    bpf_loader_upgradeable::upgrade(CpiContext::new_with_signer(
        ctx.accounts
            .bpf_loader_upgradeable_program
            .to_account_info(),
        bpf_loader_upgradeable::Upgrade {
            program: ctx.accounts.this_program.to_account_info(),
            program_data: ctx.accounts.program_data.to_account_info(),
            buffer: ctx.accounts.buffer.to_account_info(),
            authority: ctx.accounts.upgrade_authority.to_account_info(),
            spill: ctx.accounts.spill.to_account_info(),
            rent: ctx.accounts.rent.to_account_info(),
            clock: ctx.accounts.clock.to_account_info(),
        },
        &[&[
            UPGRADE_SEED_PREFIX,
            &[ctx.accounts.custodian.upgrade_authority_bump],
        ]],
    ))
}

fn handle_access_control(ctx: &Context<UpgradeContract>) -> Result<()> {
    let vaa = VaaAccount::load(&ctx.accounts.vaa)?;
    let gov_payload = crate::processor::require_valid_governance_vaa(&vaa)?;

    let upgrade = gov_payload
        .contract_upgrade()
        .ok_or(error!(CircleIntegrationError::InvalidGovernanceAction))?;

    // Make sure that the contract upgrade is intended for this network.
    require_eq!(
        upgrade.chain(),
        SOLANA_CHAIN,
        CircleIntegrationError::GovernanceForAnotherChain
    );

    // Read the implementation pubkey and check against the buffer in our account context.
    require_keys_eq!(
        Pubkey::from(upgrade.implementation()),
        ctx.accounts.buffer.key(),
        CircleIntegrationError::ImplementationMismatch
    );

    // Done.
    Ok(())
}

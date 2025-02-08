// -*- coding: utf-8 -*-
// Copyright (C) 2025 Michael Büsch <m@bues.ch>
// SPDX-License-Identifier: Apache-2.0 OR MIT

use crate::idiots::Idiot;
use anyhow::{self as ah, Context as _, format_err as err};
use nftables::{
    batch::Batch,
    expr::{Expression, NamedExpression, Payload, PayloadField},
    helper::{apply_ruleset_async, get_current_ruleset_async},
    schema::{Chain, FlushObject, NfCmd, NfListObject, NfObject, Rule},
    stmt::{Limit, Match, Operator, Statement},
    types::NfFamily,
};
use std::{borrow::Cow, collections::HashMap, fmt::Write as _, net::IpAddr, time::Instant};
use tokio::sync::Mutex;

const NFT_FAMILY: NfFamily = NfFamily::INet;
const NFT_TABLE: &str = "filter";
const NFT_CHAIN: &str = "IDIOD-INPUT";

/// Create an nftables IP source address match statement.
fn statement_match_saddr<'a>(family: NfFamily, addr: IpAddr) -> ah::Result<Statement<'a>> {
    let (protocol, addr) = match addr {
        IpAddr::V4(addr) => match family {
            NfFamily::INet | NfFamily::IP => ("ip", addr.to_string()),
            _ => {
                return Err(err!("IP version not supported by nftables firewall family"));
            }
        },
        IpAddr::V6(addr) => {
            if let Some(addr) = addr.to_ipv4_mapped() {
                match family {
                    NfFamily::INet | NfFamily::IP => ("ip", addr.to_string()),
                    _ => {
                        return Err(err!("IP version not supported by nftables firewall family"));
                    }
                }
            } else {
                match family {
                    NfFamily::INet | NfFamily::IP6 => ("ip6", addr.to_string()),
                    _ => {
                        return Err(err!("IP version not supported by nftables firewall family"));
                    }
                }
            }
        }
    };
    Ok(Statement::Match(Match {
        left: Expression::Named(NamedExpression::Payload(Payload::PayloadField(
            PayloadField {
                protocol: Cow::Borrowed(protocol),
                field: Cow::Borrowed("saddr"),
            },
        ))),
        right: Expression::String(Cow::Owned(addr)),
        op: Operator::EQ,
    }))
}

/// Create an nftables `accept` statement.
#[allow(dead_code)]
fn statement_accept<'a>() -> Statement<'a> {
    Statement::Accept(None)
}

/// Create an nftables `drop` statement.
fn statement_drop<'a>() -> Statement<'a> {
    Statement::Drop(None)
}

/// Comment string for an idiot `Rule`.
/// It can be used as unique identifier.
fn gen_comment_idiot(idiot: &FwIdiot) -> ah::Result<String> {
    let addr = idiot.addr();
    let action = "drop";

    let mut comment = String::with_capacity(256);
    write!(&mut comment, "{addr}/{action}/idiod/GENERATED")?;
    Ok(comment)
}

/// Comment string for an limiter `Rule`.
/// It can be used as unique identifier.
fn gen_comment_global_limit() -> &'static str {
    "any/limit-over-drop/idiod/GENERATED"
}

/// Generate a nftables add-rule for this idiot.
fn gen_add_idiot_cmd(idiot: &FwIdiot) -> ah::Result<NfCmd<'_>> {
    let mut rule = Rule {
        family: NFT_FAMILY,
        table: Cow::Borrowed(NFT_TABLE),
        chain: Cow::Borrowed(NFT_CHAIN),
        expr: Cow::Owned(vec![
            statement_match_saddr(NFT_FAMILY, idiot.addr())?,
            statement_drop(),
        ]),
        ..Default::default()
    };
    rule.comment = Some(Cow::Owned(gen_comment_idiot(idiot)?));
    Ok(NfCmd::Add(NfListObject::Rule(rule)))
}

fn gen_add_global_limit_cmd<'a>(packets_per_second: f32) -> ah::Result<NfCmd<'a>> {
    let packets_per_minute = (packets_per_second * 60.0)
        .round()
        .clamp(0.0, u32::MAX as f32) as u32;
    let mut rule = Rule {
        family: NFT_FAMILY,
        table: Cow::Borrowed(NFT_TABLE),
        chain: Cow::Borrowed(NFT_CHAIN),
        expr: Cow::Owned(vec![
            Statement::Limit(Limit {
                rate: packets_per_minute,
                rate_unit: None,
                per: Some(Cow::Borrowed("minute")),
                burst: None,
                burst_unit: None,
                inv: Some(true), // over
            }),
            statement_drop(),
        ]),
        ..Default::default()
    };
    rule.comment = Some(Cow::Borrowed(gen_comment_global_limit()));
    Ok(NfCmd::Add(NfListObject::Rule(rule)))
}

#[derive(Debug)]
struct ListedRuleset<'a> {
    objs: Cow<'a, [NfObject<'static>]>,
}

impl ListedRuleset<'_> {
    /// Get the active ruleset from the kernel.
    pub async fn from_kernel() -> ah::Result<Self> {
        let ruleset = get_current_ruleset_async().await?;
        Ok(Self {
            objs: ruleset.objects,
        })
    }

    /// Get the nftables handle corresponding to the comment.
    /// The rule's comment is the main identifier.
    fn find_handle(&self, comment: &str) -> ah::Result<u32> {
        for obj in &*self.objs {
            if let NfObject::ListObject(obj) = obj {
                match obj {
                    NfListObject::Rule(Rule {
                        family: rule_family,
                        table: rule_table,
                        chain: rule_chain,
                        handle: Some(rule_handle),
                        comment: Some(rule_comment),
                        ..
                    }) if *rule_family == NFT_FAMILY
                        && *rule_table == NFT_TABLE
                        && *rule_chain == NFT_CHAIN
                        && *rule_comment == comment =>
                    {
                        return Ok(*rule_handle);
                    }
                    _ => (),
                }
            }
        }
        Err(err!(
            "Nftables handle '{comment}' not found in the kernel ruleset."
        ))
    }

    /// Get the nftables handle corresponding to the idiot.
    /// The rule's comment is the main identifier.
    fn find_idiot_handle(&self, idiot: &FwIdiot) -> ah::Result<u32> {
        self.find_handle(&gen_comment_idiot(idiot)?)
    }

    fn gen_delete_cmd<'a>(&self, handle: u32) -> ah::Result<NfCmd<'a>> {
        let mut rule = Rule {
            family: NFT_FAMILY,
            table: Cow::Borrowed(NFT_TABLE),
            chain: Cow::Borrowed(NFT_CHAIN),
            expr: Cow::Owned(vec![]),
            ..Default::default()
        };
        rule.handle = Some(handle);
        Ok(NfCmd::Delete(NfListObject::Rule(rule)))
    }

    /// Generate nftables delete-rule for the global limit rule.
    pub fn gen_delete_global_limit_cmd<'a>(&self) -> ah::Result<NfCmd<'a>> {
        self.gen_delete_cmd(self.find_handle(gen_comment_global_limit())?)
    }

    /// Generate nftables delete-rule for this idiot.
    pub fn gen_delete_idiot_cmd<'a>(&self, idiot: &FwIdiot) -> ah::Result<NfCmd<'a>> {
        self.gen_delete_cmd(self.find_idiot_handle(idiot)?)
    }
}

#[derive(Debug, Clone, Copy, PartialEq)]
pub enum FwAction {
    Throttle(f32),
    Block,
}

#[derive(Debug, Clone)]
struct FwIdiot {
    pub idiot: Idiot,
    pub action: FwAction,
}

impl FwIdiot {
    pub fn new(idiot: Idiot, action: FwAction) -> Self {
        Self { idiot, action }
    }

    pub fn addr(&self) -> IpAddr {
        self.idiot.addr()
    }

    pub fn is_timed_out(&self, now: Instant) -> bool {
        self.idiot.is_timed_out(now)
    }
}

#[derive(Debug)]
struct NftFirewallInner {
    idiots: HashMap<IpAddr, FwIdiot>,
    global_limit_timeout: Option<(f32, Instant)>,
}

impl NftFirewallInner {
    async fn new() -> ah::Result<Self> {
        // Test if the `nft` binary is available.
        if let Err(e) = std::process::Command::new("nft").args(["--help"]).output() {
            return Err(err!(
                "Failed to execute the 'nft' program.\n\
                Did you install the 'nftables' support package in your distribution's package manager?\n\
                Is the 'nft' binary available in the $PATH?\n\
                The execution error was: {e}"
            ));
        }

        let mut this = Self {
            idiots: HashMap::new(),
            global_limit_timeout: None,
        };

        this.nftables_clear()
            .await
            .context("nftables initialization")?;

        Ok(this)
    }

    /// Apply a rules batch to the kernel.
    async fn nftables_apply_batch(&self, batch: Batch<'_>) -> ah::Result<()> {
        let ruleset = batch.to_nftables();
        apply_ruleset_async(&ruleset)
            .await
            .context("Apply nftables")?;
        Ok(())
    }

    /// Remove all rules from the kernel.
    async fn nftables_clear(&mut self) -> ah::Result<()> {
        let mut batch = Batch::new();

        // Remove all rules from our chain.
        batch.add_cmd(NfCmd::Flush(FlushObject::Chain(Chain {
            family: NFT_FAMILY,
            table: Cow::Borrowed(NFT_TABLE),
            name: Cow::Borrowed(NFT_CHAIN),
            ..Default::default()
        })));

        // Apply all batch commands to the kernel.
        self.nftables_apply_batch(batch).await?;

        self.idiots.clear();

        Ok(())
    }

    /// Generate one idiot rule and apply it to the kernel.
    async fn nftables_add_idiots(&self, idiots: &[&FwIdiot]) -> ah::Result<()> {
        if !idiots.is_empty() {
            let mut batch = Batch::new();
            for idiot in idiots {
                batch.add_cmd(gen_add_idiot_cmd(idiot)?);
            }

            // Apply all batch commands to the kernel.
            self.nftables_apply_batch(batch).await?;
        }
        Ok(())
    }

    /// Remove existing idiot rules from the kernel.
    async fn nftables_remove_idiots(&self, idiots: &[FwIdiot]) -> ah::Result<()> {
        if !idiots.is_empty() {
            // Get the active ruleset from the kernel.
            let ruleset = ListedRuleset::from_kernel().await?;

            // Add delete commands to remove the idiots.
            let mut batch = Batch::new();
            for idiot in idiots {
                batch.add_cmd(ruleset.gen_delete_idiot_cmd(idiot)?);
            }

            // Apply all batch commands to the kernel.
            self.nftables_apply_batch(batch).await?;
        }
        Ok(())
    }

    /// Generate a global limit rule and apply it to the kernel.
    async fn nftables_add_global_limit(&self, packets_per_second: f32) -> ah::Result<()> {
        let mut batch = Batch::new();
        batch.add_cmd(gen_add_global_limit_cmd(packets_per_second)?);

        // Apply all batch commands to the kernel.
        self.nftables_apply_batch(batch).await
    }

    /// Remove the existing global limit rule from the kernel.
    async fn nftables_remove_global_limit(&self) -> ah::Result<()> {
        let ruleset = ListedRuleset::from_kernel().await?;

        let mut batch = Batch::new();
        batch.add_cmd(ruleset.gen_delete_global_limit_cmd()?);

        // Apply all batch commands to the kernel.
        self.nftables_apply_batch(batch).await
    }

    /// Add an idiot.
    async fn add_idiot(&mut self, idiot: &Idiot, action: FwAction) -> ah::Result<FirewallAdded> {
        let idiot = FwIdiot::new(idiot.clone(), action);

        if let Some(old) = self.idiots.insert(idiot.addr(), idiot.clone()) {
            if old.action == idiot.action {
                return Ok(FirewallAdded::ExistedAlready);
            } else {
                //TODO
            }
        }

        self.nftables_add_idiots(&[&idiot]).await?;
        Ok(FirewallAdded::NewEntry)
    }

    async fn add_global_limit(
        &mut self,
        packets_per_second: f32,
        timeout: Instant,
    ) -> ah::Result<FirewallAdded> {
        if let Some((pps, global_limit_timeout)) = self.global_limit_timeout {
            if timeout > global_limit_timeout {
                self.global_limit_timeout = Some((packets_per_second, timeout));
            }
            if packets_per_second == pps {
                Ok(FirewallAdded::ExistedAlready)
            } else {
                // We assume that packets_per_second didn't change.
                unreachable!();
            }
        } else {
            self.nftables_add_global_limit(packets_per_second).await?;
            self.global_limit_timeout = Some((packets_per_second, timeout));
            Ok(FirewallAdded::NewEntry)
        }
    }

    /// Remove all timed-out idiots.
    async fn remove_timed_out_idiots(&mut self) -> ah::Result<()> {
        let now = Instant::now();

        let mut timed_out = vec![];
        self.idiots.retain(|_, idiot| {
            let to = idiot.is_timed_out(now);
            if to {
                println!("Unblocking {} (timeout)", idiot.addr());
                timed_out.push(idiot.clone());
            }
            !to
        });
        self.nftables_remove_idiots(&timed_out)
            .await
            .context("Remove nftables rule")?;

        if let Some((_, global_limit_timeout)) = self.global_limit_timeout
            && now >= global_limit_timeout
        {
            println!("Uninstalling global limit rule (timeout)");
            self.nftables_remove_global_limit()
                .await
                .context("Remove nftables global limit rule")?;
            self.global_limit_timeout = None;
        }

        Ok(())
    }

    async fn reload(&mut self) -> ah::Result<()> {
        self.nftables_clear().await?;

        {
            let idiots: Vec<&FwIdiot> = self.idiots.values().collect();
            self.nftables_add_idiots(&idiots).await?;
        }

        if let Some((packets_per_second, _)) = self.global_limit_timeout {
            self.nftables_add_global_limit(packets_per_second).await?;
        }

        Ok(())
    }

    async fn shutdown(&mut self) -> ah::Result<()> {
        self.nftables_clear().await
    }
}

#[derive(Debug, Clone, Copy)]
pub enum FirewallAdded {
    ExistedAlready,
    NewEntry,
}

#[derive(Debug)]
pub struct NftFirewall {
    inner: Mutex<NftFirewallInner>,
}

impl NftFirewall {
    /// Create a new firewall handler instance.
    /// This will also remove all rules from the kernel.
    pub async fn new() -> ah::Result<Self> {
        Ok(Self {
            inner: Mutex::new(NftFirewallInner::new().await?),
        })
    }

    /// Add an idiot.
    pub async fn add_idiot(&self, idiot: &Idiot, action: FwAction) -> ah::Result<FirewallAdded> {
        self.inner.lock().await.add_idiot(idiot, action).await
    }

    /// Add a global limit.
    pub async fn add_global_limit(
        &self,
        packets_per_second: f32,
        timeout: Instant,
    ) -> ah::Result<FirewallAdded> {
        self.inner
            .lock()
            .await
            .add_global_limit(packets_per_second, timeout)
            .await
    }

    /// Remove all timed-out idiots.
    pub async fn remove_timed_out_idiots(&self) -> ah::Result<()> {
        self.inner.lock().await.remove_timed_out_idiots().await
    }

    /// Reload all rules.
    pub async fn reload(&self) -> ah::Result<()> {
        self.inner.lock().await.reload().await
    }

    pub async fn shutdown(&self) -> ah::Result<()> {
        self.inner.lock().await.shutdown().await
    }
}

// vim: ts=4 sw=4 expandtab

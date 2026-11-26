// SPDX-License-Identifier: Apache-2.0

use std::{
    fs::{self, DirBuilder},
    os::unix::fs::DirBuilderExt as _,
    path::PathBuf,
};

use oxid_adapter_storage_identity_json::JsonDidDeploymentOperationRepository;

use super::*;

#[derive(Clone, Copy, Debug)]
enum Boundary {
    BeforeBroadcastRecord,
    BroadcastArmed,
    LostResponse,
    FinalitySaved,
    VisibilitySaved,
}

struct JournalDirectory(PathBuf);

impl JournalDirectory {
    fn new(boundary: Boundary) -> Self {
        let path = std::env::temp_dir().join(format!(
            "oxid-did-restart-{}-{boundary:?}",
            std::process::id()
        ));
        DirBuilder::new()
            .mode(0o700)
            .create(&path)
            .expect("private restart test directory");
        Self(path)
    }

    fn reopen(&self) -> Arc<JsonDidDeploymentOperationRepository> {
        Arc::new(JsonDidDeploymentOperationRepository::new(
            self.0.join("deployments.json"),
        ))
    }
}

impl Drop for JournalDirectory {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

#[derive(Debug, PartialEq, Eq)]
enum Event {
    Compose(DidDeploymentEffect),
    Fund,
    Submit,
    Reconcile(String),
    Observe,
}

#[derive(Clone, Copy)]
enum Visibility {
    Confirmed,
    Pending,
    Conflict,
}

#[derive(Clone, Copy)]
enum CompositionGate {
    Ready,
    Locked,
    Conflict,
}

struct TracedEffects {
    gate: Mutex<CompositionGate>,
    trace: Arc<Mutex<Vec<Event>>>,
    observation: Mutex<Visibility>,
}

impl DidDeploymentEffectComposer for TracedEffects {
    fn compose<'a>(
        &'a self,
        operation: &'a DidDeploymentOperation,
        account: u32,
    ) -> DidDeploymentEffectFuture<'a> {
        self.trace
            .lock()
            .unwrap()
            .push(Event::Compose(operation.effect()));
        match *self.gate.lock().unwrap() {
            CompositionGate::Ready => AllEffectsComposer.compose(operation, account),
            CompositionGate::Locked => Box::pin(async {
                Err(oxid_identity_application::DidLifecyclePortError::Locked.into())
            }),
            CompositionGate::Conflict => Box::pin(async {
                Err(map_contract_state_error(
                    PassportVaultContractStateSourceError::FinalityMismatch,
                ))
            }),
        }
    }

    fn observe<'a>(
        &'a self,
        operation: &'a DidDeploymentOperation,
    ) -> Pin<
        Box<
            dyn Future<Output = Result<DidDeploymentObservation, NativeDidDeploymentError>>
                + Send
                + 'a,
        >,
    > {
        self.trace.lock().unwrap().push(Event::Observe);
        match *self.observation.lock().unwrap() {
            Visibility::Confirmed => AllEffectsComposer.observe(operation),
            Visibility::Pending => {
                Box::pin(async { Err(NativeDidDeploymentError::IndexerPending) })
            }
            Visibility::Conflict => Box::pin(async {
                Err(map_contract_state_error(
                    PassportVaultContractStateSourceError::FinalityMismatch,
                ))
            }),
        }
    }
}

struct TracedFunding(Arc<Mutex<Vec<Event>>>);

impl MidnightContractCallFundingPort for TracedFunding {
    fn fund_contract_call(
        &self,
        request: MidnightContractCallFundingRequest,
    ) -> Result<FundedMidnightContractCall, WalletTransactionPortError> {
        self.0.lock().unwrap().push(Event::Fund);
        PassthroughFunding.fund_contract_call(request)
    }
}

struct RestoredSubmission {
    draft_id: String,
    outcome: Mutex<Result<MidnightContractCallSubmissionState, WalletTransactionPortError>>,
    trace: Arc<Mutex<Vec<Event>>>,
    completed: IncludedSubmission,
}

impl MidnightContractCallSubmissionPort for RestoredSubmission {
    fn complete_contract_call(
        &self,
        request: MidnightContractCallSubmissionRequest,
    ) -> Result<MidnightContractCallSubmissionOutcome, WalletTransactionPortError> {
        self.trace.lock().unwrap().push(Event::Submit);
        self.completed.complete_contract_call(request)
    }

    fn contract_call_submission_status(
        &self,
        _: &str,
        draft_id: &str,
    ) -> Result<MidnightContractCallSubmissionStatus, WalletTransactionPortError> {
        assert_eq!(draft_id, self.draft_id);
        Ok(IncludedSubmission::status(
            draft_id,
            (*self.outcome.lock().unwrap())?,
        ))
    }

    fn reconcile_contract_call_submission(
        &self,
        profile_id: &str,
        draft_id: &str,
    ) -> Result<MidnightContractCallSubmissionStatus, WalletTransactionPortError> {
        self.trace
            .lock()
            .unwrap()
            .push(Event::Reconcile(draft_id.to_owned()));
        self.contract_call_submission_status(profile_id, draft_id)
    }

    fn cancel_contract_call_submission(
        &self,
        _: &str,
        _: &str,
    ) -> Result<MidnightContractCallSubmissionStatus, WalletTransactionPortError> {
        panic!("restoring a DID must not cancel its submission")
    }

    fn contract_call_submission_history(
        &self,
        _: &str,
    ) -> Result<Vec<MidnightContractCallSubmissionStatus>, WalletTransactionPortError> {
        panic!("restoring a DID must reconcile by its original submission identity")
    }
}

fn interrupted_operation(
    directory: &JournalDirectory,
    boundary: Boundary,
) -> (DidDeploymentOperation, String) {
    let command = command();
    let store = directory.reopen();
    let now = UnixTimestampMillis::new(10_000);
    let mut operation = DidDeploymentOperation::new(
        DidDeploymentOperationId::parse("did-restart-test").unwrap(),
        command.profile_id,
        command.network,
        command.account_index,
        now,
    )
    .unwrap();
    store.upsert(operation.clone()).unwrap();
    let draft_id = effect_submission_id(&operation);
    let did = MidnightDid::parse(format!("did:midnight:undeployed:{}", "a".repeat(64))).unwrap();
    operation = operation.composed(did, draft_id.clone(), now).unwrap();
    store.upsert(operation.clone()).unwrap();
    for state in [DidDeploymentState::Proving, DidDeploymentState::Submitting] {
        operation = operation.transition(state, now).unwrap();
        store.upsert(operation.clone()).unwrap();
    }
    match boundary {
        Boundary::BeforeBroadcastRecord | Boundary::BroadcastArmed => {}
        Boundary::LostResponse => {
            operation = operation.outcome_unknown(now).unwrap();
            store.upsert(operation.clone()).unwrap();
        }
        Boundary::FinalitySaved | Boundary::VisibilitySaved => {
            operation = operation
                .transition(DidDeploymentState::Confirming, now)
                .unwrap();
            store.upsert(operation.clone()).unwrap();
            operation = operation
                .included("01".repeat(32), "02".repeat(32), 42, now)
                .unwrap();
            store.upsert(operation.clone()).unwrap();
            if matches!(boundary, Boundary::VisibilitySaved) {
                operation = operation
                    .observed("07".repeat(32), "02".repeat(32), 42, now)
                    .unwrap();
                store.upsert(operation.clone()).unwrap();
            }
        }
    }
    (operation, draft_id)
}

#[test]
fn restart_at_each_publication_boundary_reopens_the_journal_before_protected_work() {
    for boundary in [
        Boundary::BeforeBroadcastRecord,
        Boundary::BroadcastArmed,
        Boundary::LostResponse,
        Boundary::FinalitySaved,
        Boundary::VisibilitySaved,
    ] {
        let directory = JournalDirectory::new(boundary);
        let (interrupted, draft_id) = interrupted_operation(&directory, boundary);
        let store = directory.reopen();
        assert_eq!(store.get(interrupted.operation_id()).unwrap(), interrupted);
        let trace = Arc::new(Mutex::new(Vec::new()));
        let effects = Arc::new(TracedEffects {
            gate: Mutex::new(CompositionGate::Ready),
            trace: trace.clone(),
            observation: Mutex::new(if matches!(boundary, Boundary::FinalitySaved) {
                Visibility::Pending
            } else {
                Visibility::Confirmed
            }),
        });
        let submission = Arc::new(RestoredSubmission {
            draft_id: draft_id.clone(),
            outcome: Mutex::new(match boundary {
                Boundary::BeforeBroadcastRecord => Err(WalletTransactionPortError::DraftNotFound),
                _ => Ok(MidnightContractCallSubmissionState::Broadcasting),
            }),
            trace: trace.clone(),
            completed: IncludedSubmission {
                submissions: AtomicUsize::new(0),
            },
        });
        let coordinator = NativeDidDeploymentService::with_effects(
            effects.clone(),
            Arc::new(TracedFunding(trace.clone())),
            submission.clone(),
            Arc::new(LiveResolver { complete: true }),
            store,
            Arc::new(FixedClock),
            Arc::new(FixedRandom),
        );
        if matches!(boundary, Boundary::VisibilitySaved) {
            for (gate, failure) in [
                (
                    CompositionGate::Locked,
                    DidDeploymentFailure::ProtectionLocked,
                ),
                (
                    CompositionGate::Conflict,
                    DidDeploymentFailure::LedgerStateConflict,
                ),
            ] {
                *effects.gate.lock().unwrap() = gate;
                let paused = futures::executor::block_on(coordinator.execute(command())).unwrap();
                assert_eq!(paused.state(), DidDeploymentState::RetryableFailure);
                assert_eq!(paused.failure(), Some(failure));
                assert_eq!(paused.resume_from(), Some(DidDeploymentState::Composing));
                assert_eq!(paused.receipts(), interrupted.receipts());
                assert_eq!(paused.observations(), interrupted.observations());
                assert_eq!(
                    directory.reopen().get(interrupted.operation_id()).unwrap(),
                    paused
                );
            }
            let mut events = trace.lock().unwrap();
            assert_eq!(
                events.as_slice(),
                &[
                    Event::Compose(DidDeploymentEffect::InstallVerificationMethodVerifier),
                    Event::Compose(DidDeploymentEffect::InstallVerificationMethodVerifier),
                ]
            );
            assert_eq!(submission.completed.submissions.load(Ordering::SeqCst), 0);
            events.clear();
            *effects.gate.lock().unwrap() = CompositionGate::Ready;
        }
        let first = futures::executor::block_on(coordinator.execute(command())).unwrap();
        let events = trace.lock().unwrap();
        match boundary {
            Boundary::BeforeBroadcastRecord => {
                assert_eq!(events.as_slice(), &[Event::Reconcile(draft_id.clone())]);
                assert_eq!(first.state(), DidDeploymentState::RetryableFailure);
            }
            Boundary::BroadcastArmed | Boundary::LostResponse => {
                assert_eq!(events.as_slice(), &[Event::Reconcile(draft_id.clone())]);
                assert_eq!(first, interrupted, "{boundary:?}");
                *submission.outcome.lock().unwrap() = Ok(match boundary {
                    Boundary::BroadcastArmed => MidnightContractCallSubmissionState::Expired,
                    _ => MidnightContractCallSubmissionState::Included,
                });
            }
            Boundary::FinalitySaved => {
                assert_eq!(events.as_slice(), &[Event::Observe]);
                assert_eq!(first, interrupted);
            }
            Boundary::VisibilitySaved => {
                assert!(matches!(
                    events.as_slice(),
                    [
                        Event::Compose(DidDeploymentEffect::InstallVerificationMethodVerifier),
                        Event::Fund,
                        Event::Submit
                    ]
                ));
                assert_ne!(first.receipts()[1].submission_id(), draft_id);
            }
        }
        drop(events);

        if matches!(boundary, Boundary::FinalitySaved) {
            *effects.observation.lock().unwrap() = Visibility::Conflict;
            let blocked = futures::executor::block_on(coordinator.execute(command())).unwrap();
            assert_eq!(blocked.state(), DidDeploymentState::RetryableFailure);
            assert_eq!(
                blocked.failure(),
                Some(DidDeploymentFailure::LedgerStateConflict)
            );
            assert_eq!(
                blocked.resume_from(),
                Some(DidDeploymentState::AwaitingVisibility)
            );
            assert_eq!(blocked.receipts(), interrupted.receipts());
            assert_eq!(blocked.observations(), interrupted.observations());
            assert_eq!(
                directory.reopen().get(interrupted.operation_id()).unwrap(),
                blocked
            );
            assert_eq!(
                trace.lock().unwrap().as_slice(),
                &[Event::Observe, Event::Observe]
            );
            assert_eq!(submission.completed.submissions.load(Ordering::SeqCst), 0);
            *effects.observation.lock().unwrap() = Visibility::Confirmed;
        }

        let recovered = settle_until_resolution(&coordinator, command());
        assert_eq!(recovered.state(), DidDeploymentState::Ready, "{boundary:?}");
        assert_eq!(recovered.did(), interrupted.did(), "{boundary:?}");
        assert_eq!(recovered.receipts().len(), 8);
        assert!(recovered.receipts().starts_with(interrupted.receipts()));
        assert!(
            recovered
                .observations()
                .starts_with(interrupted.observations())
        );
        let previously_sent = matches!(
            boundary,
            Boundary::LostResponse | Boundary::FinalitySaved | Boundary::VisibilitySaved
        );
        assert_eq!(
            submission.completed.submissions.load(Ordering::SeqCst) + usize::from(previously_sent),
            8,
            "{boundary:?}"
        );
        assert_eq!(
            recovered
                .receipts()
                .iter()
                .filter(|receipt| receipt.submission_id() == draft_id)
                .count(),
            usize::from(!matches!(boundary, Boundary::BroadcastArmed)),
            "{boundary:?}"
        );
        if matches!(boundary, Boundary::LostResponse) {
            assert_eq!(recovered.receipts()[0].submission_id(), draft_id);
            assert_eq!(
                recovered.receipts()[0].transaction_hash_hex(),
                "01".repeat(32)
            );
        }
    }
}

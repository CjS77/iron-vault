# v0 acceptance index

This index maps each v0 release check in [product spec §19](iron-vault-specification.md#19-v0-user-acceptance) to the
tests, release script items and evidence files that show it. It also covers the [scope](#epic-scope) that the v0
release acceptance epic (EP-38) adds: no `dev-mode` in shipped packages, caller compatibility, and the
[implementation spec §3](implementation-specification.md#3-implementation-gates-and-unresolved-details) "Streamed
response compatibility" gate. A check is met for a release only when every case below it is shown, and the cases that
run outside `cargo test` have a recorded run in `design/evidence/`.

Each table has three columns:

- **Case**: the part of the check the row shows.
- **Shown by**: a test as `path::function`, relative to the repository root; a release script item as
  the script's path and item `name`, where `name` is the function the script's `check` line runs; or an evidence file
  in `design/evidence/`. **gap** names the ticket that adds the missing test or run. **not in v0** gives the reason the
  case cannot exist yet.
- **Runs where**: `cargo test`, `cargo test --features dev-mode`, `swtpm (ignored)`, `root + VM`,
  `owner, real hardware` or `owner, real provider keys`.

`crates/iron-vault/tests/service/acceptance_index.rs` fails when a `path::function` here names a file or function that
does not exist, so a renamed test cannot leave this index pointing at nothing. It checks script and evidence references
for the file only.

## 1. Egress to the enrolled origin and slot

> FX, Brave, and Venice requests carry the correct credential only to the enrolled origin and selected slot.

| Case | Shown by | Runs where |
|---|---|---|
| FX: query slot, the credential in the query only | `crates/iron-vault/tests/proxy/pipeline_egress.rs::fx_query_slot_sends_the_credential_in_the_query_only` | `cargo test` |
| FX: a caller-supplied copy of the query parameter is replaced | `crates/iron-vault/tests/proxy/pipeline_egress.rs::query_slot_replaces_every_caller_supplied_occurrence_of_the_parameter` | `cargo test` |
| Brave: header slot, exactly once | `crates/iron-vault/tests/proxy/pipeline_egress.rs::brave_header_slot_sends_the_credential_in_its_header_exactly_once` | `cargo test` |
| Brave over HTTP/2, to the enrolled authority only | `crates/iron-vault/tests/proxy/pipeline_egress.rs::brave_over_http2_sends_the_credential_to_the_enrolled_authority_only` | `cargo test` |
| Venice: bearer slot, streamed POST | `crates/iron-vault/tests/proxy/pipeline_egress.rs::venice_bearer_slot_forwards_the_post_body_byte_for_byte_and_streams_the_reply` | `cargo test` |
| Basic slot replaces the caller's `Authorization` | `crates/iron-vault/tests/proxy/pipeline_egress.rs::basic_slot_replaces_the_callers_authorization_with_one_basic_value` | `cargo test` |
| A token caller on a loopback listener reaches its route | `crates/iron-vault/tests/proxy/pipeline_egress.rs::a_token_caller_on_the_loopback_listener_reaches_its_route` | `cargo test` |
| Generated requests go only to the route's upstream, with the slot written once | `crates/iron-vault-policy/tests/policy/destination.rs::checked_requests_go_only_to_the_route_upstream`, `crates/iron-vault-policy/tests/policy/destination.rs::checked_requests_write_the_slot_exactly_once` | `cargo test` |
| A record's permitted origins bound the destination | `crates/iron-vault-policy/tests/policy/destination.rs::omitted_origins_never_produce_a_checked_request` | `cargo test` |
| Through `add` and `config approve` on the running service, three upstreams on distinct hosts at once, each credential only to its own origin and slot and no other credential in any scrubbed form | `crates/iron-vault/tests/proxy/release_egress.rs::fx_brave_and_venice_each_carry_only_their_own_credential_to_their_enrolled_origin_and_slot` | `cargo test` |
| A Unix peer-account caller reaches its granted route and is refused another with no upstream connection | `crates/iron-vault/tests/proxy/release_egress.rs::a_peer_account_caller_reaches_its_route_and_no_other` | `cargo test` |
| Real FX, Brave and Venice providers | **gap**: K-373 | `owner, real provider keys` |

## 2. No credentialed egress for hostile requests

> Unauthenticated and ungranted requests, traversal, header overrides, wrong markers, and mismatched final URLs produce
> no credentialed egress.

| Case | Shown by | Runs where |
|---|---|---|
| Unauthenticated: missing or wrong token | `crates/iron-vault/tests/proxy/pipeline_egress.rs::a_missing_or_wrong_token_is_401` | `cargo test` |
| Ungranted route | `crates/iron-vault/tests/proxy/pipeline_egress.rs::a_route_the_caller_is_not_granted_is_403` | `cargo test` |
| Unknown prefix | `crates/iron-vault/tests/proxy/pipeline_egress.rs::a_prefix_no_route_has_is_404` | `cargo test` |
| Traversal, through the proxy | `crates/iron-vault/tests/proxy/pipeline_egress.rs::hostile_paths_are_400_before_any_upstream_work`, `crates/iron-vault/tests/proxy/pipeline_egress.rs::an_absolute_form_or_authority_form_target_is_refused_before_any_upstream_work` | `cargo test` |
| Traversal, generated, at the policy level | `crates/iron-vault-policy/tests/policy/hostile_paths.rs::accepted_escape_soup_never_reads_as_traversal`, `crates/iron-vault-policy/tests/policy/hostile_paths.rs::authorized_paths_stay_under_the_upstream_base` | `cargo test` |
| Header overrides | `crates/iron-vault/tests/proxy/pipeline_egress.rs::override_rewrite_and_forwarding_headers_are_stripped_not_refused`, `crates/iron-vault-policy/tests/policy/destination.rs::caller_host_header_keeps_every_property` | `cargo test` |
| Wrong markers | `crates/iron-vault/tests/proxy/pipeline_egress.rs::a_marker_naming_another_credential_in_the_slot_is_400`, `crates/iron-vault-policy/tests/policy/destination.rs::slot_filled_through_another_route_is_refused` | `cargo test` |
| Mismatched final URL: the final check refuses it and raises an event | `crates/iron-vault-policy/src/final_check/tests.rs::a_host_other_than_the_upstreams_is_refused`, `crates/iron-vault-policy/src/final_check/tests.rs::a_path_other_than_the_authorized_one_is_refused`, `crates/iron-vault/src/pipeline/tests/refusal.rs::a_final_check_failure_raises_a_high_severity_event_without_secrets` | `cargo test` |
| Generated hostile requests through the proxy, checked at the recording upstream: unauthenticated and ungranted callers, traversal and long paths, absolute- and authority-form targets, override headers, wrong markers and methods | `crates/iron-vault/tests/proxy/hostile_egress.rs::generated_hostile_requests_produce_no_credentialed_egress` | `cargo test` |

A mismatched final URL has no egress-level test. The pipeline builds the outgoing URL structurally from the selected
route's upstream and re-checks it, so no request through the public API produces one, and the proxy has no test hook to
miswire a route. The "Mismatched final URL" row shows the case where a mismatch can be built: the final check refusing
a request whose host or path differs from the authorized one, and the pipeline turning a final-check failure into a
high-severity event that names no secret.

## 3. Trusted paths and the desktop user

> The package rejects user-writable trusted paths; the desktop user cannot read service memory or vault records through
> ordinary account permissions.

| Case | Shown by | Runs where |
|---|---|---|
| Trusted-path rules: group-writable ancestors, symlinks, readable lock files | `crates/iron-vault/tests/service/trusted_path.rs::a_group_writable_ancestor_fails_naming_it`, `crates/iron-vault/tests/service/trusted_path.rs::a_user_owned_symlink_to_the_state_dir_is_untrusted`, `crates/iron-vault/tests/service/trusted_path.rs::a_lock_file_readable_by_others_fails` | `cargo test` |
| `serve` refuses an unsafe state or config directory | `crates/iron-vault/tests/service/serve_refusal.rs::a_state_directory_other_accounts_can_read_is_refused_by_path`, `crates/iron-vault/tests/service/serve_refusal.rs::a_config_directory_other_accounts_can_write_is_refused_by_path`, `crates/iron-vault/tests/service/serve_refusal.rs::a_config_file_other_accounts_can_write_is_refused_by_path` | `cargo test --features dev-mode` |
| The package's units and directories pass the rules | `crates/iron-vault/tests/service/package_units.rs::service_unit_has_every_required_directive`, `crates/iron-vault/tests/service/package_units.rs::tmpfiles_directories_pass_the_trusted_path_rules` | `cargo test` |
| The process is not dumpable | `crates/iron-vault/tests/service/hardening.rs::harden_process_disables_dumps_and_skips_locking_under_a_finite_limit` | `cargo test` |
| Installed: a group-writable `/etc/iron-vault` is refused at restart | `scripts/release/linux-install-check.sh` item `group_writable_config_is_refused` | `root + VM` |
| Installed: the test account cannot open `/proc/PID/mem`, `/proc/PID/environ` or `/var/lib/iron-vault` | `scripts/release/linux-install-check.sh` item `open_is_denied` | `root + VM` |
| Installed: not dumpable, `LimitCORE=0`, memory locked | `scripts/release/linux-install-check.sh` items `process_not_dumpable`, `core_dumps_are_off`, `memory_is_locked` | `root + VM` |
| A recorded run of the install check | **gap**: K-372 | `root + VM` |

## 4. Restrictions under concurrency and touch

> Rate limits and path/method restrictions apply under concurrency; unavailable touch requirements never degrade to
> unconfirmed access.

| Case | Shown by | Runs where |
|---|---|---|
| Concurrent requests never exceed a bucket | `crates/iron-vault/tests/proxy/pipeline_egress.rs::concurrent_requests_cannot_exceed_a_bucket` | `cargo test` |
| Path and method restrictions, one request at a time | `crates/iron-vault-policy/src/authorization.rs::method_and_path_restrictions_apply`, `crates/iron-vault/src/pipeline/tests.rs::a_method_off_the_allowlist_is_refused_before_authorization` | `cargo test` |
| A rate-limited request is refused unsent | `crates/iron-vault/src/pipeline/tests.rs::a_rate_limited_request_is_not_resolved` | `cargo test` |
| A touch route never activates without a provider | `crates/iron-vault-policy/src/activation.rs::touch_route_is_refused_without_a_provider` | `cargo test` |
| Allowed and forbidden paths and methods racing on one route: only allowed requests reach the upstream, one per `200` | `crates/iron-vault/tests/proxy/release_restrictions.rs::allowed_and_forbidden_requests_racing_on_one_route_reach_the_upstream_only_when_allowed` | `cargo test` |
| Two callers on one route share its bucket (§8), and the upstream count never exceeds it | `crates/iron-vault/tests/proxy/release_restrictions.rs::two_callers_on_one_route_share_its_bucket` | `cargo test` |
| An approval narrowing a route while requests run: nothing the new policy forbids is admitted after it, a request both policies forbid is never admitted, and no approval hands out a fresh burst | `crates/iron-vault/tests/proxy/release_restrictions.rs::an_approval_that_narrows_a_route_while_requests_run_admits_nothing_the_new_policy_forbids` | `cargo test` |
| `config approve` refuses a touch route, naming it, and the previous config keeps serving | `crates/iron-vault/tests/proxy/release_restrictions.rs::config_approve_refuses_a_touch_route_and_keeps_serving_the_previous_config` | `cargo test` |
| A committed config with a touch route leaves the service Unavailable, every request `503`, no upstream connection | `crates/iron-vault/tests/proxy/release_restrictions.rs::a_committed_touch_route_leaves_the_service_unavailable_with_no_upstream_connection` | `cargo test` |
| A touch-confirmed request | **not in v0**: no confirmation provider exists, so a touch route is refused at activation | |

## 5. Scrubbing

> Scrubbing handles supported representations, compression, and arbitrary stream chunk boundaries while preserving
> ordinary streaming responses.

| Case | Shown by | Runs where |
|---|---|---|
| Representations: raw, Basic token, URL-encoded | `crates/iron-vault/tests/proxy/proxy_scrub.rs::the_secret_its_basic_token_and_its_url_encoded_form_are_all_replaced` | `cargo test` |
| Every derived form (raw, `%XX` both cases, each base64 variant; Basic token forms) in a header and the body | `crates/iron-vault/tests/proxy/proxy_scrub.rs::every_derived_form_echoed_in_a_header_and_the_body_is_replaced_in_both` | `cargo test` |
| A reply without the secret is unchanged | `crates/iron-vault/tests/proxy/proxy_scrub.rs::a_reply_without_the_secret_comes_back_unchanged_but_for_its_framing_integrity_and_etag_headers` | `cargo test` |
| Any chunking matches one-shot scrubbing | `crates/iron-vault/src/scrub/tests.rs::any_chunking_matches_one_shot` | `cargo test` |
| HTTP/1.1 body split at every byte offset | `crates/iron-vault/tests/proxy/proxy_scrub_stream.rs::a_body_split_at_every_byte_offset_scrubs_to_the_same_bytes` | `cargo test` |
| HTTP/2 body split at every byte offset across two DATA frames | `crates/iron-vault/tests/proxy/proxy_scrub_stream.rs::an_http2_body_split_at_every_byte_offset_across_two_data_frames_scrubs_to_the_same_bytes` | `cargo test` |
| SSE events relayed one at a time; a streamed reply arrives unchanged | `crates/iron-vault/tests/proxy/proxy_scrub_stream.rs::an_sse_event_reaches_the_caller_before_the_next_one_is_sent`, `crates/iron-vault/tests/proxy/proxy_scrub_stream.rs::a_streamed_chat_completion_without_the_secret_arrives_unchanged_and_in_at_least_as_many_chunks` | `cargo test` |
| HTTP/2: SSE events relayed one at a time; a streamed reply arrives unchanged | `crates/iron-vault/tests/proxy/proxy_scrub_stream.rs::an_http2_sse_event_reaches_the_caller_before_the_next_one_is_sent`, `crates/iron-vault/tests/proxy/proxy_scrub_stream.rs::an_http2_streamed_chat_completion_without_the_secret_arrives_unchanged_and_in_at_least_as_many_chunks` | `cargo test` |
| gzip, deflate and br decoded and scrubbed | `crates/iron-vault/tests/proxy/proxy_coding.rs::gzip_deflate_and_br_bodies_reach_the_caller_decoded_and_scrubbed` | `cargo test` |
| Decompression bombs and truncated bodies | `crates/iron-vault/tests/proxy/proxy_coding.rs::a_decompression_bomb_aborts_the_connection_before_a_secret_planted_past_the_limit`, `crates/iron-vault/tests/proxy/proxy_coding.rs::a_truncated_gzip_body_aborts_the_connection` | `cargo test` |
| gzip, deflate and br split at every compressed offset | `crates/iron-vault/tests/proxy/proxy_coding_stream.rs::a_gzip_body_split_at_every_compressed_offset_scrubs_to_the_same_bytes`, `crates/iron-vault/tests/proxy/proxy_coding_stream.rs::a_deflate_body_split_at_every_compressed_offset_scrubs_to_the_same_bytes`, `crates/iron-vault/tests/proxy/proxy_coding_stream.rs::a_br_body_split_at_every_compressed_offset_scrubs_to_the_same_bytes` | `cargo test` |
| gzip SSE relayed one event at a time | `crates/iron-vault/tests/proxy/proxy_coding_stream.rs::a_gzip_sse_event_reaches_the_caller_decoded_before_the_next_is_sent` | `cargo test` |

## 6. Approval counters

> Old config/signature pairs fail after a newer approval; counters survive restart, failed signing, and key replacement
> without reuse.

| Case | Shown by | Runs where |
|---|---|---|
| An old pair fails after a newer approval, on reload and on restart | `crates/iron-vault/tests/credentials/approval_release.rs::a_version_1_pair_put_back_after_version_2_is_refused_on_sighup`, `crates/iron-vault/tests/credentials/approval_release.rs::a_version_1_pair_put_back_after_version_2_is_refused_on_restart` | `cargo test` |
| Counters survive restart | `crates/iron-vault/tests/credentials/approval_release.rs::the_next_version_after_a_restart_is_higher` | `cargo test` |
| A failed signer consumes its version | `crates/iron-vault/tests/credentials/approval_release.rs::a_version_consumed_by_a_failed_stage_or_a_failed_signer_is_never_reused_across_restarts`, `crates/iron-vault-store/src/approval/transaction/tests.rs::a_failed_signer_consumes_its_version_and_stages_nothing` | `cargo test` |
| Key replacement keeps the counters | `crates/iron-vault/tests/credentials/approval_release.rs::rotating_the_approver_keeps_the_counters_and_the_active_signature_needs_a_new_approval` | `cargo test` |
| An older committed pair at startup is not served | `crates/iron-vault/tests/service_context_linux.rs::an_older_committed_pair_at_startup_is_unavailable_and_the_old_policy_is_not_served` | `cargo test` |

The approver commands' own release checks are in [approval-signers.md](approval-signers.md#release-checks).

## 7. Power failure around the approval commit

> Power failure before the approval commit retains the previous committed policy; power failure after the commit
> completes that exact transaction or keeps the service unavailable. Recovery never activates an uncommitted version.

| Case | Shown by | Runs where |
|---|---|---|
| Before the commit: the previous policy is kept | `crates/iron-vault/tests/credentials/approval_release.rs::a_power_cut_before_the_commit_keeps_the_previous_committed_policy` | `cargo test` |
| After the commit: completed or unavailable | `crates/iron-vault/tests/credentials/approval_release.rs::a_power_cut_after_the_commit_completes_that_transaction_or_keeps_the_service_unavailable` | `cargo test` |
| Power loss after every call of the transaction | `crates/iron-vault-store/src/approval/transaction/tests.rs::power_loss_after_every_call_leaves_the_previous_approval_or_a_finishable_new_one`, `crates/iron-vault-store/src/approval/recovery/tests.rs::power_loss_after_every_call_of_an_approval_recovers_the_committed_approval` | `cargo test` |
| Config directory writes survive a crash at every point | `crates/iron-vault-store/src/config_dir_faults.rs::publish_survives_a_crash_at_every_point` | `cargo test` |
| An uncommitted version is never activated | `crates/iron-vault/tests/service_context_linux.rs::an_uncommitted_higher_version_at_startup_is_unavailable`, `crates/iron-vault/tests/service_context_linux.rs::a_reload_to_a_validly_signed_uncommitted_higher_version_goes_unavailable`, `crates/iron-vault-store/src/approval/recovery/tests.rs::a_staged_approval_never_committed_is_discarded_and_its_version_stays_consumed` | `cargo test` |

## 8. Recovery and passphrase envelopes

> Recovery opens the vault through an independent recipient; passphrase envelopes never create an invalid
> mixed-recipient `age` file.

| Case | Shown by | Runs where |
|---|---|---|
| The recovery key opens the vault in Ready and in Locked | `crates/iron-vault/tests/signers/recovery_check.rs::the_right_key_opens_the_vault_in_ready_and_in_locked_and_changes_nothing_else` | `cargo test` |
| A rotated recovery key works and the old one does not | `crates/iron-vault/tests/signers/recipients.rs::after_rotating_the_recovery_key_the_new_key_passes_recovery_check_and_the_old_fails` | `cargo test` |
| Mixed scrypt and X25519 stanzas are refused | `crates/iron-vault-store/src/envelope.rs::a_scrypt_stanza_beside_x25519_is_refused`, `crates/iron-vault-store/src/envelope.rs::stanza_kinds_lists_one_x25519_per_recipient_and_one_grease` | `cargo test` |
| Compose host unlock: `identity.age` has three X25519 stanzas and no scrypt stanza; the recovery key opens the vault | `scripts/release/compose-unlock-check.sh` items `identity_has_three_x25519_stanzas`, `recovery_key_opens_the_same_vault`; `design/evidence/compose-unlock-check-2026-11-11.md` | `root + VM` |
| After `recipient add`, `add --host-unlock`, `add --recovery`, `recipient remove`, `approver add` and `approver remove`, `identity.age` has one X25519 stanza per listed recipient and no scrypt stanza, each passphrase envelope has exactly one scrypt stanza, and the current recovery key opens the Locked vault; the replaced key does not once removed | `crates/iron-vault/tests/signers/rewrap_stanzas.rs::identity_age_stays_x25519_only_and_the_recovery_key_opens_the_vault_after_every_rewrap` | `cargo test` |
| Not covered there: a vault passphrase change (v0 has no command), and `approver add` of a `tpm` approver (needs a TPM) | not shown by a `cargo test` | not run |

## 9. Second writers, damaged records and directory fsync

> A second writer fails; a damaged credential does not overwrite healthy records; every durable rename includes its
> directory fsync.

| Case | Shown by | Runs where |
|---|---|---|
| A second service on one state directory fails | `crates/iron-vault/tests/service_context_linux.rs::a_second_service_on_the_same_state_directory_fails_to_start`, `crates/iron-vault-store/src/state_dir.rs::second_acquire_is_held_and_names_path` | `cargo test` |
| A second config writer is refused | `crates/iron-vault-store/src/config_dir.rs::a_second_writer_is_refused_until_the_first_drops` | `cargo test` |
| Installed: a second `serve` fails on the state lock | `scripts/release/linux-install-check.sh` item `second_instance_fails_on_lock` | `root + VM` |
| A damaged record leaves the others healthy | `crates/iron-vault/tests/service_context_linux.rs::a_damaged_record_is_damaged_with_its_routes_unavailable_and_the_others_stay_healthy`, `crates/iron-vault/tests/service_context_linux.rs::one_damaged_credential_record_gives_503_on_its_routes_while_unrelated_routes_reach_the_upstream` | `cargo test` |
| `replace` repairs a damaged name | `crates/iron-vault-store/src/vault/write_tests.rs::a_damaged_name_is_taken_and_replace_repairs_it` | `cargo test` |
| Every rename syncs its directory, in the store's durable writes | `crates/iron-vault-store/src/durable_faults.rs::trace_properties_hold`, `crates/iron-vault-store/src/durable_faults.rs::trace_properties_catch_a_missing_directory_fsync`, `crates/iron-vault-store/src/config_dir_faults.rs::writes_follow_the_durable_discipline` | `cargo test` |
| `add`, `replace` and `rm` beside a truncated, bit-flipped or foreign-recipient record succeed and leave every other record file byte-identical, the damaged one still listed damaged | `crates/iron-vault/tests/credentials/damaged_neighbours.rs::release_check_9_add_beside_a_damaged_record_leaves_the_other_records_byte_identical`, `crates/iron-vault/tests/credentials/damaged_neighbours.rs::release_check_9_replace_beside_a_damaged_record_leaves_the_other_records_byte_identical`, `crates/iron-vault/tests/credentials/damaged_neighbours.rs::release_check_9_rm_beside_a_damaged_record_leaves_the_other_records_byte_identical` | `cargo test` |
| `replace` and `rm` of the damaged record's name succeed and leave both healthy record files byte-identical; `list` then shows it healthy after `replace` and no longer lists it after `rm` | `crates/iron-vault/tests/credentials/damaged_neighbours.rs::release_check_9_replace_of_the_damaged_record_heals_it_and_leaves_the_healthy_records_byte_identical`, `crates/iron-vault/tests/credentials/damaged_neighbours.rs::release_check_9_rm_of_the_damaged_record_removes_it_and_leaves_the_healthy_records_byte_identical` | `cargo test` |
| `recipient add` and `recipient remove` beside a damaged record succeed and leave every record file byte-identical | `crates/iron-vault/tests/credentials/damaged_neighbours.rs::release_check_9_recipient_add_beside_a_damaged_record_leaves_every_record_byte_identical`, `crates/iron-vault/tests/credentials/damaged_neighbours.rs::release_check_9_recipient_remove_beside_a_damaged_record_leaves_every_record_byte_identical` | `cargo test` |
| `export` beside a damaged record refuses before any prompt, naming the record file, and leaves every record file byte-identical | `crates/iron-vault/tests/credentials/damaged_neighbours.rs::release_check_9_export_refuses_a_damaged_record_by_name_and_leaves_every_record_byte_identical` | `cargo test` |
| `reset` beside a damaged record proceeds from Ready and discards every record file | `crates/iron-vault/tests/credentials/damaged_neighbours.rs::release_check_9_reset_beside_a_damaged_record_proceeds_and_discards_every_record` | `cargo test` |
| Every rename, link and unlink in a whole session syncs its directory before the step reports success: init, unlock, add, replace, rm, config approve, lock, approver add and remove, recipient add and remove, recovery check, export with its bundle file, import into a second vault, reset | `crates/iron-vault/tests/lifecycle/session_dir_sync.rs::every_rename_and_unlink_in_a_whole_session_syncs_its_directory` | `cargo test` |
| The fault filesystem links like the real one, and the trace check skips only failed calls | `crates/iron-vault-store/src/fault_fs.rs::hard_link_refuses_an_existing_name_and_needs_a_dir_sync`, `crates/iron-vault-store/src/fault_fs.rs::succeeded_since_leaves_out_failed_calls` | `cargo test` |

## 10. Export and import

> Export/import preserves records, counters, recovery access, and the service boundary without writing plaintext
> secret artifacts.

Each part is one test in `crates/iron-vault/tests/lifecycle/migration.rs`; [migration-bundle.md](migration-bundle.md#release-checks)
says what each proves.

| Case | Shown by | Runs where |
|---|---|---|
| Records | `crates/iron-vault/tests/lifecycle/migration.rs::export_import_preserves_records` | `cargo test` |
| Counters | `crates/iron-vault/tests/lifecycle/migration.rs::export_import_preserves_counters` | `cargo test` |
| Recovery access | `crates/iron-vault/tests/lifecycle/migration.rs::import_recovery_key_opens_destination` | `cargo test` |
| Service boundary; no plaintext secret written | `crates/iron-vault/tests/lifecycle/migration.rs::export_bundle_holds_no_plaintext_secret`, `crates/iron-vault/tests/lifecycle/migration.rs::import_routes_only_after_new_approval` | `cargo test` |

## 11. Source-owner authorization

> Export and destination-recipient enrollment reject missing, incorrect, expired, replayed, or cancelled source-owner
> authorization, including when the vault is already unlocked. Each supported TPM PIN, YubiKey touch, or
> original-passphrase method must authorize only its pending migration. A new export passphrase or an earlier unlock
> must never authorize export on its own.

[migration-authorization.md](migration-authorization.md#release-checks) maps each case to its mechanism; the rejection
suite has one test per row.

| Case | Shown by | Runs where |
|---|---|---|
| Missing, incorrect, expired, replayed; the vault already unlocked; a new export passphrase | `crates/iron-vault/tests/lifecycle/migration_rejection.rs::missing_authorization_has_no_way_to_start`, `crates/iron-vault/tests/lifecycle/migration_rejection.rs::incorrect_approval_passphrase_in_place_of_the_vault_passphrase_is_denied`, `crates/iron-vault/tests/lifecycle/migration_rejection.rs::expired_between_the_prompt_and_the_check_is_denied`, `crates/iron-vault/tests/lifecycle/migration_rejection.rs::replayed_proof_and_replayed_challenge_are_refused`, `crates/iron-vault/tests/lifecycle/migration_rejection.rs::an_unlocked_vault_does_not_authorize_without_a_fresh_proof`, `crates/iron-vault/tests/lifecycle/migration_rejection.rs::a_new_export_passphrase_never_authorizes` | `cargo test` |
| Cancelled | `crates/iron-vault/tests/lifecycle/migration_prompt.rs::no_owner_input_cancels_with_no_authorization_and_retires_the_challenge`, `crates/iron-vault/tests/lifecycle/migration_prompt.rs::a_lock_at_the_prompt_is_unavailable_and_records_no_failure` | `cargo test` |
| The passphrase authorizes only its pending migration | `crates/iron-vault/tests/lifecycle/migration_rejection.rs::bound_an_export_proof_is_refused_for_add_recipient`, `crates/iron-vault/tests/lifecycle/migration_rejection.rs::bound_a_proof_for_one_destination_is_refused_for_another` | `cargo test` |
| The TPM PIN authorizes only its pending migration | `crates/iron-vault/tests/lifecycle/migration_tpm_pin.rs::a_signature_over_another_message_never_authorizes`, `crates/iron-vault/tests/lifecycle/migration_tpm_pin.rs::a_pin_answer_takes_its_challenge_once`, `crates/iron-vault/tests/lifecycle/migration_tpm_pin.rs::a_pin_answer_after_the_challenge_expires_is_refused_before_the_tpm_signs` | `cargo test` |
| The TPM PIN through the real helper | `crates/iron-vault/tests/lifecycle/migration_tpm_pin.rs::the_real_helper_authorizes_a_migration_by_pin_and_denies_a_wrong_one` | `swtpm (ignored)` |
| `recipient add`: wrong passphrase, cancelled, unlocked vault alone, another key's authorization | `crates/iron-vault/tests/signers/recipient_add.rs::a_wrong_vault_passphrase_adds_nothing`, `crates/iron-vault/tests/signers/recipient_add.rs::a_cancelled_prompt_adds_nothing_and_releases_the_lock`, `crates/iron-vault/tests/signers/recipient_add.rs::an_unlocked_vault_alone_never_adds_a_key_because_the_prompt_comes_first`, `crates/iron-vault/tests/signers/recipient_add.rs::an_authorization_for_another_key_or_operation_never_reaches_the_rewrap` | `cargo test` |
| `recipient add`: expired at the prompt, through the real command | `crates/iron-vault/tests/signers/recipient_add.rs::a_passphrase_typed_after_the_challenge_expired_adds_nothing` | `cargo test` |
| `recipient add`: expired before the rewrap; the exchange has no prompt between the proof and the rewrap, so this drives the `add_recipient` the handler calls | `crates/iron-vault/tests/signers/recipient_add.rs::an_authorization_that_expires_before_the_rewrap_adds_nothing` | `cargo test` |
| `recipient add`: replayed; the authorization is move-only and the binding digest never reaches the client, so a replay cannot be sent through the command and its `not_pending` audit record is unreachable there; this drives the service the handler calls | `crates/iron-vault/tests/signers/recipient_add.rs::a_challenge_used_for_one_add_is_refused_for_a_second` | `cargo test` |
| YubiKey touch | **not in v0**: no hardware-key provider exists; `approver add` refuses hardware signers as unavailable | |

## 12. Explicit safe states

> Locked startup, invalid policy, TLS failures, unsafe listener configurations, and ownership failures produce explicit
> safe states.

| Case | Shown by | Runs where |
|---|---|---|
| Locked startup answers 503 before reaching the upstream | `crates/iron-vault/tests/service_context_linux.rs::startup_without_an_unlock_is_locked_and_answers_503_before_reaching_the_upstream`, `crates/iron-vault/tests/service_context_linux.rs::locked_startup_stays_locked_after_a_wrong_passphrase` | `cargo test` |
| Invalid policy is Unavailable with a redacted reason | `crates/iron-vault/tests/service_context_linux.rs::an_invalid_approval_leaves_the_service_unavailable_with_its_listeners_bound`, `crates/iron-vault/tests/service_context_linux.rs::a_bad_signature_at_startup_is_unavailable_with_policy_invalid`, `crates/iron-vault/tests/service_context_linux.rs::an_unparsable_config_starts_locked_with_no_request_listeners_and_a_working_admin_socket` | `cargo test` |
| Upstream TLS failure, at the client | `crates/iron-vault/tests/upstream/upstream_client.rs::an_upstream_certificate_from_another_ca_is_a_tls_failure`, `crates/iron-vault/tests/upstream/upstream_client.rs::the_built_in_roots_refuse_a_private_ca` | `cargo test` |
| Listener TLS: mismatched or unsafe key and certificate files | `crates/iron-vault/src/listener_tls/tests.rs::a_key_that_does_not_match_the_certificate_is_refused`, `crates/iron-vault/src/listener_tls/tests.rs::a_key_file_readable_by_others_is_refused_by_its_trusted_path_rule` | `cargo test` |
| Unsafe listeners: plain HTTP off loopback; a protected install binding TCP itself | `crates/iron-vault/src/request_listeners/tests.rs::open_each_refuses_plain_http_off_loopback_and_opens_the_rest`, `crates/iron-vault/src/request_listeners/tests.rs::a_protected_install_refuses_to_bind_tcp_itself_and_closes_what_it_opened` | `cargo test` |
| Ownership failures stop `serve`, naming the path | `crates/iron-vault/tests/service/serve_refusal.rs::a_state_directory_other_accounts_can_read_is_refused_by_path`, `crates/iron-vault/tests/service/serve_refusal.rs::a_log_directory_other_accounts_can_read_stops_serve_before_any_record_or_socket` | `cargo test --features dev-mode` |
| A protected build without its service account names it | `crates/iron-vault/tests/service/deployment_profile.rs::a_protected_build_without_the_service_account_names_it` | `cargo test` |
| Upstream TLS through the proxy: a certificate from another CA, for another name, or expired is `502` `upstream_tls`, and the recording upstream gets a connection but no request | `crates/iron-vault/tests/proxy/release_safe_states.rs::an_upstream_certificate_from_another_ca_is_502_upstream_tls_with_nothing_sent`, `crates/iron-vault/tests/proxy/release_safe_states.rs::an_upstream_certificate_for_another_name_is_502_upstream_tls_with_nothing_sent`, `crates/iron-vault/tests/proxy/release_safe_states.rs::an_expired_upstream_certificate_is_502_upstream_tls_with_nothing_sent` | `cargo test` |
| An approved TLS listener off loopback with a mismatched, missing or exposed key never opens: Locked safe state before unlock, Ready on the other listeners after it, with a warning naming why | `crates/iron-vault/tests/service_context_linux.rs::an_approved_tls_listener_whose_key_does_not_match_its_certificate_never_opens`, `crates/iron-vault/tests/service_context_linux.rs::an_approved_tls_listener_whose_key_file_cannot_be_read_never_opens` | `cargo test` |
| A plain-HTTP listener off loopback: `config approve` refuses it and the previous config keeps serving; an unapproved published one never opens at startup | `crates/iron-vault/tests/proxy/release_safe_states.rs::config_approve_refuses_a_plain_http_listener_off_loopback_and_keeps_serving_the_previous_config`, `crates/iron-vault/tests/service_context_linux.rs::an_unapproved_plain_http_listener_off_loopback_never_opens_at_startup` | `cargo test` |

## Epic scope

The v0 release acceptance epic (EP-38) adds three parts to the §19 checks.

### Packages without `dev-mode`

Every shipped package is built without `dev-mode`: its `iron-vault --version` lists no such feature.

| Case | Shown by | Runs where |
|---|---|---|
| `--version` names the enabled features | `crates/iron-vault/tests/service/deployment_profile.rs::version_names_the_enabled_features` | `cargo test` |
| The Debian package build refuses a binary that lists features | `scripts/build-deb.sh` | `root + VM` (run on the build machine before the install check) |
| CI's release build lists neither `dev-mode` nor `container` | `.github/workflows/ci.yml` step "Release build has no development mode" | `cargo test` (in CI) |
| The Compose image build refuses a binary that lists more than `container` | `packaging/compose/Dockerfile` | `root + VM` (built by `scripts/release/compose-check.sh`) |
| Installed: `--version` lists no features | `scripts/release/linux-install-check.sh` item `version_lists_no_features` | `root + VM` |
| The package checks shown to refuse a `dev-mode` binary; the Compose check re-reads the built image's `--version` | **gap**: K-370 | `cargo test` |
| A recorded run of the install check | **gap**: K-372 | `root + VM` |

### Caller compatibility

Only tested combinations are documented as supported
([implementation spec §3](implementation-specification.md#3-implementation-gates-and-unresolved-details) "Caller
compatibility").

| Case | Shown by | Runs where |
|---|---|---|
| FX MCP, Brave MCP and Venice clients through Iron Vault: a check script and a compatibility page | **gap**: K-371 | `owner, real provider keys` |
| FX, Brave and Venice with real keys; a Naomi static caller | **gap**: K-373 | `owner, real provider keys` |

### Streamed response compatibility

The implementation spec §3 gate asks for measured overlap buffering, decompression limits, SSE latency, rewritten
headers and supported encodings. [secret-handling.md](secret-handling.md#streamed-response-compatibility) holds the
figures.

| Case | Shown by | Runs where |
|---|---|---|
| Bytes held back per chunk | `crates/iron-vault/tests/proxy/proxy_scrub_stream.rs::measure_bytes_held_back_per_chunk` | `cargo test` |
| SSE latency, identity and gzip | `crates/iron-vault/tests/proxy/proxy_scrub_stream.rs::measure_sse_latency_per_event`, `crates/iron-vault/tests/proxy/proxy_coding_stream.rs::measure_gzip_sse_latency_per_event` | `cargo test` |
| Decompression limits and throughput | `crates/iron-vault/tests/proxy/proxy_coding_stream.rs::the_default_limits_accept_a_10_mib_gzip_json_reply`, `crates/iron-vault/tests/proxy/proxy_coding_stream.rs::measure_gzip_decode_throughput`, `crates/iron-vault/tests/proxy/proxy_coding_stream.rs::a_decompression_bomb_is_cut_off_with_no_chunk_over_one_decoder_step_plus_the_hold_back` | `cargo test` |
| SSE latency from an HTTP/2 upstream | `crates/iron-vault/tests/proxy/proxy_scrub_stream.rs::measure_http2_sse_latency_per_event` | `cargo test` |
| SSE latency, deflate and br | `crates/iron-vault/tests/proxy/proxy_coding_stream.rs::measure_deflate_and_br_sse_latency_per_event` | `cargo test` |
| A figure from a real target API | **gap**: K-373 | `owner, real provider keys` |

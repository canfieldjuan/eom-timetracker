# EOM customer create match: slice B plan (tracker)

Slice B of the accepted customer create match contract
([`EOM_CUSTOMER_CREATE_MATCH_CONTRACT.md`](./EOM_CUSTOMER_CREATE_MATCH_CONTRACT.md),
PR 287; issue 282). One PR. It merges only after Atlas slice A (ATLAS PR 2548)
is live on the office `atlas-api`, because every request that sends `onMatch`
needs Atlas's `contact.match_without_write` and is refused with 501 without it.

## What changes

- **The reservation records its `onMatch`.**
  - New nullable column `eom_customer_atlas_reservations.atlas_on_match`, with
    a CHECK that admits only `'return'`. It is added in the schema
    initializer with `ADD COLUMN IF NOT EXISTS`.
  - `_reserve_customer_atlas_creation` writes `'return'` on every new
    reservation, in both 0C modes.
  - Reservations created before this slice stay null.
- **One request per reservation.** `_atlas_operator_contact_body` copies the
  reservation's recorded value into `onMatch`, or sends none when it is null.
  Retries rebuild the body from the reservation, so the first send and every
  retry are the same request under the same key.
- **The capability gate follows the request.**
  - `_customer_atlas_capability_refusal` takes the `onMatch` the request will
    carry. With one, it proves `contact.operator_mutation` and
    `contact.match_without_write` on the operator-contacts route from one
    manifest read. Without one, it checks exactly as before.
  - Create and reconcile pass the value a new reservation records.
  - Retry passes the reservation's own value, so a pre-slice reservation still
    needs only 0C's capability.
  - An unreadable manifest still reserves and attempts (0C).
- **Leads-page customer create.**
  - `_funnel_contact_create_on_match` is the one predicate: a customer
    create without `contactId` sends `"return"`; lead creates and every edit
    send nothing. Both the request body and the strict gate read it.
  - On `contact_matched` the route returns 409 `funnel_contact_exists`, with
    `details: {contactId, fullName}` and a message that names the contact
    ("Nothing was changed. Open that contact to edit it."). The app's error
    handler puts the message in `error`, which the portal shows.
- **The gate's own clear-field branch.** It now appends to the required
  capabilities instead of replacing them, so it cannot drop a requirement
  added before it. Today clears exist only on edits and `onMatch` only on
  creates, so no request changes.
- **Not changed:**
  - **The finalizer.** Its ownership check already refuses a contact another
    Customer holds, and a public-onboarding reservation, after Atlas answers.
  - **The post-link identity sync.**
  - **Customer-type change.**

## Decisions

- **A column, not a payload key.** A CHECK constraint makes an invalid
  recorded value unrepresentable, and the reservation's `payload` stays the
  Customer's own details.
- **The deploy order is enforced by the gate, not by a fallback.** A tracker
  ahead of Atlas refuses with 501. It never sends a create without `onMatch`
  as a fallback, because that is exactly the overwrite this contract removes.

## Review contract coverage (tracker items)

| Item | Test (`backend/test_customer_create_match.py` unless noted) |
|---|---|
| 8 | `test_create_matching_a_held_contact_is_refused_and_writes_nothing` |
| 9 | `test_create_matching_an_unheld_contact_links_and_sends_only_the_bill_to` |
| 10 | `test_reconcile_sends_on_match_and_refuses_a_held_match` |
| 11 | `test_leads_customer_create_matching_a_contact_is_refused_with_it_named`, `test_leads_lead_create_and_every_edit_send_no_on_match`; `contact_created` body in `backend/test_funnel_contact_creation.py::test_manual_customer_create_omits_blank_optional_fields_and_never_creates_a_tracker_customer` |
| 12 | `test_each_on_match_request_needs_the_capability` (create, reconcile, Leads customer create), `test_an_unreadable_manifest_still_reserves_with_the_recorded_on_match` |
| 13 | `backend/test_customer_atlas_creation.py::test_customer_create_sends_the_agreed_atlas_contract`, `::test_a_first_time_create_returns_the_legacy_response_shape` |
| 14 | `test_customer_type_change_body_carries_no_on_match` |
| 15 | `test_a_reservation_from_before_the_contract_retries_its_original_request`, `test_a_new_reservation_sends_return_on_its_first_attempt_and_its_retry`, `test_the_recorded_on_match_admits_only_return` |

Atlas-side behavior (a match writes nothing) is proven by slice A's tests;
these tests use a fake Atlas that answers as slice A does, and assert what the
tracker sends and writes.

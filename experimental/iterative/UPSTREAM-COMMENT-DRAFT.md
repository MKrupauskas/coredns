I would like to revisit this from the external-plugin-first direction discussed
above. The use case is opt-in root-to-authority iteration in a static Go
CoreDNS binary, avoiding a separate resolver process and dependence on a
public recursive service's quotas. This would not imply unlimited authority
capacity or immediate inclusion in the default build.

I have prepared a small, isolated lab adapter that reuses a pinned SDNS
validating resolver and its cache pipeline. It builds with CGO disabled and
has local adapter tests, selected signed-hierarchy engine tests, and a public
network smoke test. It is not production-ready: lifecycle/global pipeline
state, strict short-TTL semantics, aggregate memory budgets and adapter-level
conformance still need work. A fresh validator implementation seems a larger
review and maintenance risk than extracting a suitable engine API.

The accompanying design describes referral-loop termination, shared work
budgets for DNSSEC and auxiliary lookups, cache ownership/TTL/provenance,
root trust-anchor rollover, admission policy and staged conformance tests.
My proposed first engineering milestone is an instance-scoped engine API plus
a deterministic signed root/TLD/child adapter harness, before expanding the
Corefile interface or discussing default shipping.

Is an independently maintained external plugin still the preferred direction,
and would you prefer continuing the design here or opening a narrowly scoped
tracking issue linked to #2216? I would also appreciate guidance on engine
ownership and whether the answer cache should initially remain inside the
validating engine to preserve its metadata contract.

This file is a prepared comment, not a posted message. Add the fork draft PR
link when posting after reviewing the experiment's scope and limitations.

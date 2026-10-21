# varmor-classifier and BehaviorModeling

## Role

The official Chart deploys the classifier as a Deployment behind a Service. Agents call it to classify random path elements during local behavior preprocessing; agents then report their results to the manager, which aggregates cross-node data into APM/Profiles. The classifier does not need a Pod on each node and does not report modeling results to the manager itself. It is not a prerequisite for ordinary EnhanceProtect/RuntimeDefault/AlwaysAllow protection.

## Modeling chain

```text
Target workload behavior -> agent/audit/BPF collection -> agent preprocessing (calls classifier Service for random paths) -> agent reports to manager -> manager aggregation, profile generation, persistence -> ArmorProfileModel -> subsequent analysis or DefenseInDepth
```

Failure at any stage may look like "no modeling data", but the causes differ.

## Prerequisites

Check containerd, BTF, audit-log sources, BehaviorModeling flags, agent node coverage, and classifier Deployment/Service availability and resources. Large behavior datasets may use local disk instead of inline CRD storage; interpret visibility using `storageType`.

## Typical failures

- **Classifier absent**: abnormal only when behavior modeling is enabled;
- **Node not covered by an agent**: that node's behavior cannot contribute to a complete model;
- **Classifier unavailable**: inspect Service endpoints and agent-to-classifier requests. The current preprocessor retains the original path when classification fails, so this may reduce path generalization without preventing all modeling data;
- **Running but no data**: distinguish collection capability, audit source, agent preprocessing/reporting, manager receipt, and persistence;
- **Modeling never completes**: correlate policy phase, duration, whether target Pods re-entered modeling, APM desired/completed/ready, and manager logs;
- **Transition fails after completion**: transitions between BehaviorModeling and other modes have lifecycle restrictions; use policy status and validation for the actual version.

Behavior modeling describes observed behavior only. It proves neither completeness nor that observed actions should be allowed.

## Recommendations only

Establish collection-chain health and data completeness before considering model-based Profile generation or changes. Do not equate completed modeling with active protection, or replace least-privilege review with observed data without approval.

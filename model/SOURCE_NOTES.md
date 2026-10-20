# Package scope and provenance

Published 21 October 2026 from the locally frozen Model V3 experiment. Model weights, runtime inference logic and saved evaluation values are preserved (text line endings are normalized to LF for Git portability); server-specific documentation and the example identity are adapted for this repository. The source archive was not retrained or modified.

Included: trained main/behavior artifacts, inference helpers, pinned model dependencies, schema/freeze/protocol files, synthetic evaluation summaries, historical implementation decisions and one small synthetic 22-day inference example.

Not included: private RealTime/Harmonized archives, original endpoint mappings, full fitting/evaluation datasets, alternate V1/V2/V4 weights, the educational walkthrough or a live server adapter. `train.py` is retained unchanged because `predict.py` imports its scoring/ranking helpers; its training entrypoint belongs to the original research workspace and refuses to overwrite frozen runs. This folder is a frozen inference package, not a standalone regeneration bundle. Do not run training here expecting the omitted generator/data/baseline dependencies to be present.

Historical reports may mention paths to sibling research experiments and an earlier task's no-push statement. Those statements describe the original experiment; this publication does not change its frozen metrics or readiness status. `PACKAGE_MANIFEST.json` lists current published hashes. Original freeze files pin the exact main and behavior weight hashes. No server runtime behavior changes as part of this model-only addition.

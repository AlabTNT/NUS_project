# Final supervised fingerprint model

The finalized experiment, dataset statement, 5|1 results, all 15 4|2 splits,
Magic-generation analysis, and deployment commands are documented in:

```text
../PROJECT_FINAL_REPORT.md
```

Train and reproduce all evaluations:

```powershell
py -3 .\lock\fingerprint_door.py train `
  --data-root .\fingerprint_data_mix `
  --model-dir .\fingerprint_models\mix_supervised_binary `
  --group-metadata .\fingerprint_data_mix\group_metadata.json
```

Run the finalized model:

```powershell
py -3 .\lock\fingerprint_door.py use `
  --config .\lock\config\Mix.txt `
  --model .\fingerprint_models\mix_supervised_binary\final_all_groups\supervised_binary_model.json `
  --output-dir .\fingerprint_use_mix
```

The deployment model is a group/class-balanced L2 logistic classifier over the
concatenated AUTH A, AUTH B, and READ block-0 feature vectors.

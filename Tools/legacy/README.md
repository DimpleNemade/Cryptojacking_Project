# Quarantined legacy pipelines

`Tools/full_pipeline_backup.py` and `Scripts/run_yara.sh` were removed from normal
use. The backup pipeline interpolated user input into commands executed with
`shell=True`; the standalone YARA script also created a competing report path.

Historical copies remain available in Git history and the dissertation appendix.
Neither is a supported entry point. Use one of these equivalent primary entry
points instead:

```bash
python3 -m cryptojacking_forensics --memory FILE --case-id CASE_ID
./Scripts/run_pipeline.sh FILE CASE_ID
```

`Appendix_Artefacts/` is retained as a historical snapshot and is not executable
project code.


# Exact-version GitHub publishing (manual; no repository was changed here)

Use the GitHub account that owns the repository. Verify the target repository URL from Appendix C before proceeding. Never force-push a student's existing history merely to upload this ZIP.

1. Download/unzip the corrected project into an approved working directory. Do not place a second `ByteProbe/` folder within the existing repository unexpectedly.
2. On a copy of the repository run `git status`, `git remote -v`, `git branch --show-current` and `git log -1 --format='%H %ad %s' --date=iso`; save the output with the project documentation.
3. Copy the corrected contents into the repository root or a new branch. Retain any authentic historical commits and clearly preserve the original author's contribution history.
4. Run the complete tests, compare generated results and hashes, then `git add -A`, `git diff --cached --stat` and `git diff --cached --check`. Remove private evidence files, keys, personal Windows paths or accidental raw forensic images before committing.
5. `git commit -m "Improve ByteProbe scientific validation and reproducibility"`; `git push origin <your-branch>`. Replace `<your-branch>` with the real branch name, do not paste the angle brackets literally.
6. Visit the commit online, ensure the source file tree includes `core/mft.py`, `core/timeline.py`, `evaluation/compare_mftecmd.py`, `evaluation/evaluate_controlled_timestamps.py`, `tools/run_windows_checks.py`, the whole test suite, and supporting results. Record the **remote** SHA and URL, update Appendix C and test all links. A local commit alone is not remote proof.

The above is a procedure, **not evidence of a push**. No GitHub credentials were supplied with this archive.

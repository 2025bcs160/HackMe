# HackMe Cybersecurity Learning Toolkit

This repository contains a local learning environment for practicing web security testing with intentionally vulnerable applications.

## Contents

- `learning_setup/` — Learning environment with vulnerable Flask apps, setup scripts, and scanner tests
- `sql_injection_tester/` — CLI scanner for SQL injection and XSS testing
- `vulnerable.db` — Sample SQLite database used by the learning apps

## Quick Start

1. Open a terminal in the repository root.
2. Run the setup script:
   ```batch
   cd learning_setup
   setup_and_run.bat
   ```
3. In another terminal, run the XSS lab:
   ```batch
   python vulnerable_xss_app.py
   ```
4. Run the scanner tests:
   ```batch
   run_tests.bat
   ```

## External Target Scanning

This tool can scan external `.com` websites when you have explicit authorization.
Use the `--confirm-authorization` flag to confirm you have permission:

```batch
cd sql_injection_tester
python main.py scan-url --url "https://example.com/search?q=test" --confirm-authorization
```

## Recommended Workflow

- Start `learning_setup/vulnerable_app.py` for the SQL injection lab.
- Start `learning_setup/vulnerable_xss_app.py` for the XSS lab.
- Use `sql_injection_tester/main.py` to run scanning commands.
- Read `learning_setup/CYBERSECURITY_LEARNING_GUIDE.md` for guided exercises.

## Notes

- Only test this environment on your own machine.
- Do not run these vulnerable apps on public servers.
- Always obtain permission before testing real applications.

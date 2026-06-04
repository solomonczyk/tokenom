# Runtime Validation

Tokenom runtime validation uses dummy-only data. Do not use production API keys,
real private project data, or paid provider traffic during validation.

## Environment

Use an isolated virtual environment. On Windows, keep the environment path short
to avoid path-length issues with large dependency trees:

```powershell
python -m venv C:\tmp\tokenom-venv
C:\tmp\tokenom-venv\Scripts\python.exe -m pip install --upgrade pip maturin
C:\tmp\tokenom-venv\Scripts\python.exe -m pip install pytest pytest-asyncio pytest-cov pydantic click rich tiktoken litellm==1.82.3 fastapi uvicorn httpx websockets opentelemetry-api tomli pyyaml
```

## Native Core

The Headroom Python extension is built with maturin:

```powershell
$env:Path = "$env:USERPROFILE\.cargo\bin;$env:Path"
$env:VIRTUAL_ENV = "C:\tmp\tokenom-venv"
C:\tmp\tokenom-venv\Scripts\python.exe -m maturin develop --release
```

On Windows this requires Visual Studio Build Tools with the C++ workload because
the MSVC Rust target needs `link.exe`. If `link.exe` is unavailable, the native
core cannot be accepted as validated.

## Checks

Run focused security and runtime validation tests:

```powershell
$env:PYTHONPATH = (Get-Location).Path
C:\tmp\tokenom-venv\Scripts\python.exe -m pytest tests\test_tokenom_security.py tests\test_tokenom_runtime_validation.py -q
C:\tmp\tokenom-venv\Scripts\python.exe benchmarks\tokenom_dummy_benchmark.py
C:\tmp\tokenom-venv\Scripts\python.exe -m tokenom.runtime_validation
```

Artifacts are written under `artifacts/runtime_validation/`.

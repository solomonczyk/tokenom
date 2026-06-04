# Windows native core build

Tokenom includes the compiled `headroom._core` extension from the upstream Rust/Python package. On Windows, build it from a Visual Studio developer environment so `cl.exe`, `link.exe`, the Windows SDK libraries, Rust, Cargo, Python, and maturin are all visible to the same process.

## Requirements

- Visual Studio 2022 Build Tools with the MSVC v143 C++ toolchain.
- Windows 10 or Windows 11 SDK. This validation used SDK `10.0.18362.0`.
- Rust and Cargo from rustup.
- Python virtual environment with maturin installed.
- No production API keys or private provider traffic are required.

## Validated command

From the repository root, run the build through `vcvars64.bat`:

```bat
cmd /v:on /c "call C:\BuildTools\VC\Auxiliary\Build\vcvars64.bat && set ""PATH=%USERPROFILE%\.cargo\bin;C:\tmp\tokenom-venv\Scripts;!PATH!"" && set ""VIRTUAL_ENV=C:\tmp\tokenom-venv"" && C:\tmp\tokenom-venv\Scripts\python.exe -m maturin develop --release"
```

Then validate the extension import:

```bat
C:\tmp\tokenom-venv\Scripts\python.exe -c "import headroom._core; print('core ok')"
```

## Common failures

- `link.exe` not found: run from the Visual Studio developer environment or call `vcvars64.bat` before maturin.
- `cannot open input file 'kernel32.lib'`: install or repair the Windows SDK and rerun the developer environment initialization.
- Rust or Cargo not found: add `%USERPROFILE%\.cargo\bin` to the same command environment used for maturin.

The compiled `.pyd` and Cargo `target/` directory are local build outputs and are intentionally not committed.

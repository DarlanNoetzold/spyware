from cx_Freeze import setup, Executable

build_exe_options = {"packages": ["os"], "includes": ["csv"]}

base = None

setup(
    name="block_DNS",
    version="0.1",
    description="block_DNS",
    options={"build_exe": build_exe_options},
    executables=[Executable("block_DNS.py", base=base)]
)
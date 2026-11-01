# obfuscate_837.pyw -- Windows launcher that opens the GUI without a console window.
# Double-click it, or drop an 837 file / folder onto it.  Same behaviour as
# running obfuscate_837.py with no arguments.
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from obfuscate_837 import gui, main  # noqa: E402

argv = sys.argv[1:]
if not argv:
    gui()
elif len(argv) == 1 and os.path.exists(argv[0]):
    gui(initial_input=argv[0])
else:
    sys.exit(main(argv))

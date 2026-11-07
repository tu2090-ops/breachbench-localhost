"""Allow running BreachBench via `python -m breachbench`."""
import sys
from breachbench.cli import main

if __name__ == "__main__":
    sys.exit(main())

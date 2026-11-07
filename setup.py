from pathlib import Path
from setuptools import find_packages, setup

README_PATH = Path(__file__).resolve().parent / "README.md"

setup(
    name="breachbench",
    version="1.3.0",
    description="Open-source security benchmark, 3-layer Guardrail Shield, and static/dynamic scanner for AI agents, code vulnerabilities, malware, phishing, and OWASP API Top 10.",
    long_description=README_PATH.read_text(encoding="utf-8") if README_PATH.exists() else "",
    long_description_content_type="text/markdown",
    author="Tanushree Umathe",
    url="https://github.com/tu2090-ops/breachbench",
    project_urls={
        "Homepage": "https://github.com/tu2090-ops/breachbench",
        "Repository": "https://github.com/tu2090-ops/breachbench",
        "Issues": "https://github.com/tu2090-ops/breachbench/issues",
        "Changelog": "https://github.com/tu2090-ops/breachbench/blob/main/CHANGELOG.md",
    },
    license="MIT",
    classifiers=[
        "Development Status :: 5 - Production/Stable",
        "Intended Audience :: Developers",
        "Intended Audience :: Information Technology",
        "Intended Audience :: Science/Research",
        "License :: OSI Approved :: MIT License",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.9",
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: 3.11",
        "Programming Language :: Python :: 3.12",
        "Programming Language :: Python :: 3.13",
        "Programming Language :: Python :: 3.14",
        "Topic :: Security",
    ],
    packages=find_packages(include=["breachbench*", "app*", "labs*"]),
    include_package_data=True,
    python_requires=">=3.9",
    install_requires=[
        "fastapi>=0.110.0",
        "pydantic>=2.6.0",
        "uvicorn>=0.27.0",
        "httpx>=0.27.0",
    ],
    entry_points={
        "console_scripts": [
            "breachbench=breachbench.cli:main",
        ],
    },
)

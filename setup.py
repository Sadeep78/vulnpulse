from setuptools import setup, find_packages

setup(
    name="vulnpulse",
    version="2.0.0",
    description="High-performance, threat-enriched CLI tool for Common Vulnerabilities and Exposures (CVEs)",
    long_description=open("README.md", encoding="utf-8").read(),
    long_description_content_type="text/markdown",
    author="Sadeep78",
    packages=find_packages(),
    python_requires=">=3.8",
    entry_points={
        "console_scripts": [
            "vulnpulse=vulnpulse.cli:main",
        ],
    },
    extras_require={
        "dev": ["pytest>=7.0.0"],
    },
    classifiers=[
        "Programming Language :: Python :: 3",
        "License :: Other/Proprietary License",
        "Operating System :: OS Independent",
        "Topic :: Security",
    ],
)

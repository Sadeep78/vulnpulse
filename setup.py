from setuptools import setup, find_packages

setup(
    name="vulnhound",
    version="2.0.0",
    description="High-performance, threat-enriched CLI tool for Common Vulnerabilities and Exposures (CVEs)",
    long_description=open("README.md", encoding="utf-8").read(),
    long_description_content_type="text/markdown",
    author="Security Engineering Team",
    packages=find_packages(),
    python_requires=">=3.8",
    entry_points={
        "console_scripts": [
            "vulnhound=vulnhound.cli:main",
        ],
    },
    extras_require={
        "dev": ["pytest>=7.0.0"],
    },
    classifiers=[
        "Programming Language :: Python :: 3",
        "License :: OSI Approved :: MIT License",
        "Operating System :: OS Independent",
        "Topic :: Security",
    ],
)

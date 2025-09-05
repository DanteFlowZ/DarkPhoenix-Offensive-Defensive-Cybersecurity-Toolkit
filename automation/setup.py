# setup.py
from setuptools import setup, find_packages
import pathlib

here = pathlib.Path(__file__).parent.resolve()
long_description = (here / "README.md").read_text(encoding="utf-8")

setup(
    name="darkphoenix-cybersecurity",
    version="1.0.0",
    description="Advanced Offensive & Defensive Cybersecurity Toolkit",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/tuusuario/darkphoenix",
    author="Pablo",
    author_email="tuemail@example.com",
    classifiers=[
        "Development Status :: 4 - Beta",
        "Intended Audience :: Cybersecurity Professionals",
        "Topic :: Security :: Cybersecurity Framework",
        "License :: OSI Approved :: MIT License",
        "Programming Language :: Python :: 3.8",
        "Programming Language :: Python :: 3.9",
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: 3.11",
    ],
    keywords="cybersecurity, pentesting, threat hunting, siem, pcap analysis",
    packages=find_packages(where="."),
    python_requires=">=3.8, <4",
    install_requires=[
        "aiohttp>=3.8.0",
        "scapy>=2.5.0", 
        "paramiko>=3.0.0",
        "pandas>=1.5.0",
        "matplotlib>=3.6.0",
        "cryptography>=38.0.0",
        "requests>=2.28.0",
        "dnspython>=2.3.0",
        "seaborn>=0.12.0",
    ],
    extras_require={
        "dev": ["black", "flake8", "pytest", "pytest-asyncio"],
        "docs": ["sphinx", "sphinx-rtd-theme"],
        "web": ["flask", "fastapi", "uvicorn"],
    },
    entry_points={
        "console_scripts": [
            "darkphoenix-recon=offensive.recon:main",
            "darkphoenix-threat-hunter=defensive.threat_hunter:main",
            "darkphoenix-pcap=defensive.pcap_analyzer:main",
        ],
    },
    project_urls={
        "Bug Reports": "https://github.com/tuusuario/darkphoenix/issues",
        "Source": "https://github.com/tuusuario/darkphoenix",
    },
)

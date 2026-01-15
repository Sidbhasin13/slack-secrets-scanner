"""Setup script for slack-secrets-scanner."""

from setuptools import setup, find_packages

# Use UTF-8 encoding for cross-platform compatibility
with open("README.md", "r", encoding="utf-8") as fh:
    long_description = fh.read()

with open("requirements.txt", "r", encoding="utf-8") as fh:
    requirements = [line.strip() for line in fh if line.strip() and not line.startswith("#")]

setup(
    name="slack-secrets-scanner",
    version="1.0.0",
    author="Slack Secrets Scanner Contributors",
    description="Slack secrets scanner with entropy-based verification",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/yourusername/slack-secrets-scanner",
    packages=find_packages(),
    classifiers=[
        "Development Status :: 4 - Beta",
        "Intended Audience :: Developers",
        "Intended Audience :: Information Technology",
        "Topic :: Security",
        "License :: OSI Approved :: GNU General Public License v2 (GPLv2)",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.8",
        "Programming Language :: Python :: 3.9",
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: 3.11",
        "Operating System :: OS Independent",
        "Operating System :: Microsoft :: Windows",
        "Operating System :: POSIX :: Linux",
        "Operating System :: MacOS",
    ],
    python_requires=">=3.8",
    install_requires=requirements,
    entry_points={
        "console_scripts": [
            "slack-secrets-scanner=slack_secrets_scanner.cli:main",
        ],
    },
)


from setuptools import find_packages, setup

setup(
    name="phishing-detection-backend",
    version="0.1.0",
    packages=find_packages(),
    install_requires=[
        "fastapi",
        "uvicorn",
        "scikit-learn",
        "pandas",
        "numpy",
        "requests",
        "joblib",
        "tldextract",
        "pydantic",
        "watchdog",
    ],
)

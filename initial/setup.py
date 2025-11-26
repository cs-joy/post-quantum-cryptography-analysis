# setup.py
from setuptools import setup, find_packages

setup(
    name="pqc_compare",
    version="0.1",
    packages=find_packages(),
    install_requires=[
        "numpy",
        "pandas",
        "matplotlib",
        "seaborn",
        "web3",
        "psutil", # Added dependency from requirements.txt
    ],
    # Add path to liboqs shared library
    # NOTE: This assumes a specific local build path for liboqs
    # and is primarily for development convenience.
    # For distribution, managing the liboqs dependency would require a different approach.
    package_data={
        # This line attempts to bundle the library, but it's generally not recommended
        # for external dependencies like this. Users should typically install liboqs separately.
        # "pqc_compare": ["../liboqs/build/lib/*"], # Commented out - rely on system path or LD_LIBRARY_PATH
    },
    entry_points={
        'console_scripts': [
            'pqc_benchmark=blockchain_benchmark:main', # Example entry point if needed
            'pqc_visualize=visualization:main',      # Example entry point if needed
        ],
    }
)
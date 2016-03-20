from setuptools import setup, find_packages

setup(
    name="maid",
    description="Cloud Maid - Policy Rules Engine",
    version='1.0',
    packages=find_packages(),
    entry_points={
        'console_scripts': [
            'cloud-maid = maid.cli:main']},
    requires=["boto3", "pyyaml"],
)


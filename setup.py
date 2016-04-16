from setuptools import setup, find_packages

setup(
    name="c7n",
    description="Cloud Custodian - Policy Rules Engine",
    version='1.0',
    packages=find_packages(),
    entry_points={
        'console_scripts': [
            'custodian = c7n.cli:main']},
    requires=["boto3", "pyyaml"],
)


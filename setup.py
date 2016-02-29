from setuptools import setup, find_packages

setup(
    name="janitor",
    description="Cloud instance tag policy janitor",
    version='1.0',
    packages=find_packages(),
    entry_points={
        'console_scripts': [
            'cloud-maid = janitor.cli:main']},
    requires=["boto3", "pyyaml"],
)


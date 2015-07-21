from setuptools import setup, find_packages

setup(
    name="janitor",
    description="Cloud instance tag policy janitor",
    version='0.0',
    packages=find_packages(),
    entry_points={
        'console_scripts': [
            'cloud-janitor = janitor.cli:main']},
    requires=["boto", "pyyaml"],
    test_requires=["mock"],
)


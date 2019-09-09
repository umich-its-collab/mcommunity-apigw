import os

from subprocess import check_output

from setuptools import setup, find_packages

version = check_output(['bash', os.path.join(os.path.dirname(__file__), 'version.sh')]).decode(encoding='utf-8')

with open(os.path.join(os.path.dirname(__file__), 'README.md'), 'r') as f:
    long_description = f.read()

test_deps = [
    'pytest',
    'pytest-pep8',
    'flask',
]

setup(
    name='mcommunity',
    version=version,
    description='Library for interacting with MCommunity APIs',
    long_description=long_description,
    long_description_content_type='text/markdown',
    url='https://gitlab.umich.edu/carleski/python-mcommunity.git',
    author='Rob Carleski',
    author_email='carleski@umich.edu',
    license='MIT',
    python_requires='>=3',
    packages=find_packages(),
    install_requires=[
        'requests',
        'ldap3'
    ],
    setup_requires=[
        'pytest-runner',
    ],
    tests_require=test_deps,
    extras_require={
        'test': test_deps,
    },
    zip_safe=False
)

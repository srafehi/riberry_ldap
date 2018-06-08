from setuptools import setup, find_packages

setup(
    name='riberry-ldap',
    version='0.0.1',
    author='Shady Rafehi',
    url='https://github.com/srafehi/riberry_ldap',
    author_email='shadyrafehi@gmail.com',
    packages=find_packages(),
    install_requires=[
        'ldap3',
        'riberry',
    ],
    dependency_links=[
        'http://github.com/srafehi/riberry/tarball/master#egg=riberry'
    ]
)

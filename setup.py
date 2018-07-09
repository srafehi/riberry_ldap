from setuptools import setup, find_packages

setup(
    name='riberry-ldap',
    version='0.1.0',
    author='Shady Rafehi',
    url='https://github.com/srafehi/riberry_ldap',
    author_email='shadyrafehi@gmail.com',
    packages=find_packages(),
    install_requires=[
        'riberry',
        'ldap3',
    ],
    dependency_links=[
        'http://github.com/srafehi/riberry/tarball/master#egg=riberry'
    ]
)

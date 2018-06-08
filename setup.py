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
        'http://github.com/srafehi/riberry_ldap/tarball/master#egg=riberry_ldap',
    ],
)

# Copyright (c) Aaron Gallagher <_@habnab.it>
# See COPYING for details.

from setuptools import setup


with open('README.rst', 'rb') as infile:
    long_description = infile.read()

with open('requirements.txt', 'rb') as infile:
    install_requires = infile.read().split()

setup(
    name='scrapy_socks',
    description='Scrapy socks proxy support',
    license='Apache 2.0',
    install_requires=install_requires,
    packages=['scrapy_socks'],
)

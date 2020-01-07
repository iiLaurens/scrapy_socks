# Copyright (c) Aaron Gallagher <_@habnab.it>
# See COPYING for details.

from setuptools import setup

with open('requirements.txt', 'r') as infile:
    install_requires = infile.readlines()

setup(
    name='scrapy_socks',
    description='Scrapy socks proxy support',
    license='Apache 2.0',
    install_requires=install_requires,
    packages=['scrapy_socks'],
)

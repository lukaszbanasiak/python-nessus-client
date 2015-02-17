import os
import os.path
import nessus

from setuptools import setup, find_packages


def readme(fname):
    """Utility function to read the README file.

    Used for the long_description. It's nice, because now 1) we have a top level
    README file and 2) it's easier to type in the README file than to put a raw
    string in below ...

    :param fname: README file
    :return: README text
    """
    return open(os.path.join(os.path.dirname(__file__), fname)).read()

setup(
    name='python-nessus-client',
    version=nessus.__version__,
    description='Python Client for Nessus REST API',
    author=nessus.__author__,
    author_email='lukas.banasiak@gmail.com',
    url='https://github.com/lukaszbanasiak/python-nessus-client',
    packages=find_packages(),
    include_package_data=True,
    zip_safe=False,
    long_description=readme('README.rst'),
    license='MIT',
    keywords='nessus api rest client',
    install_requires=['requests', ],
    classifiers=[
        'Development Status :: 3 - Alpha',
        'Environment :: Web Environment',
        'Intended Audience :: Developers',
        'License :: OSI Approved :: MIT License',
        'Operating System :: OS Independent',
        'Programming Language :: Python',
        'Programming Language :: Python :: 2',
        'Programming Language :: Python :: 2.7',
        'Topic :: Internet :: WWW/HTTP',
        'Topic :: Security',
        'Topic :: Software Development :: Libraries :: Python Modules',
    ],
)


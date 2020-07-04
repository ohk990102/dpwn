import io
from setuptools import find_packages, setup

setup(name='pwntools-addon-dockerized',
      version='0.1',
      description='Make process-like tube with Docker for awesome heap challenges, and more!',
      license='MIT',
      packages=find_packages(),
      zip_safe=False)
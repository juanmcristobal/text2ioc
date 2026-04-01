# Use Ubuntu 22.04 to keep Python package availability current
FROM ubuntu:22.04

# Set environment variables
ENV DEBIAN_FRONTEND=noninteractive

# Set the working directory inside the container
WORKDIR /app

# Update the package list and install essential packages
RUN apt-get update && apt-get install -y \
    software-properties-common \
    curl \
    && apt-get clean

# Add the deadsnakes PPA for multiple Python versions
RUN add-apt-repository -y ppa:deadsnakes/ppa

# Update the package list again to include the new repository
RUN apt-get update

# Install Python versions used by tox in this project template
RUN apt-get install -y \
    python3.10 \
    python3.11 \
    python3.12 \
    python3.13 \
    && apt-get clean

# Set Python 3.10 as the default python version
RUN update-alternatives --install /usr/bin/python3 python3 /usr/bin/python3.10 1

# Install pip for Python 3.10
RUN curl https://bootstrap.pypa.io/get-pip.py -o get-pip.py
RUN python3.10 get-pip.py

# Install tox for Python 3
RUN python3 -m pip install tox

# Set the default command to run tox
CMD ["tox"]

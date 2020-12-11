import setuptools

with open("README.md", "r") as fh:
    long_description = fh.read()

setuptools.setup(
    name="flydns",
    version="0.2",
    author="Pham Sy Minh",
    author_email="phamminh0227@gmail.com",
    description="Find related subdomains from subdomains",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/shelld3v/flydns",
    packages=setuptools.find_packages(),
    entry_points={
        "console_scripts": [
            "flydns=flydns.__main__:main",
        ]
    },
    install_requires=["tldextract","argparse","termcolor","dnspython","ipwhois"],
    classifiers=[
        "Programming Language :: Python :: 3.4",
        "License :: OSI Approved :: Apache Software License",
        "Operating System :: OS Independent",
        "Topic :: Security"
    ],
)

from setuptools import setup, find_packages
setup(
    name='osshhapi',
    version='0.0.1',
    install_requires=[
        'requests',
        'netmiko',
        'Jinja2',
        'PyYAML',
        'urllib3'
        'ciscoconfparse'
    ],
    packages=find_packages(),
    package_dir={"src": "src"},
    package_data={"src.resources": ["**/*.py", "**/*.json", "**/*.yml", "**/*.textfsm", "**/*.j2", "**/*.json"],
                  },
    include_package_data=True
)
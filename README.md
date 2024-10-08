# ECSTATS

ECstats is a tool for extracting ElasticCache database metrics. The script is able to process all the Redis databases, both single instance, replicated and clustered ones that belong to specific AWS region. Multiple regions can be defined in the configuration. 

The script will purely query cloudwatch for the metrics. It will never connect to the Redis databases and it will NOT send any commands to the databases.

This script by no means will affect the performance and the data stored in the Redis databases it is scanning.

The script will need at minimum CloudwatchReadOnlyAccess & AmazonElastiCacheReadOnlyAccess privilleges for extracting the information.


## Installation

There are couple of ways to run the script which are mentioned as below:

### 1. Running the script from source

**Pre-requisites:** The script will run on any system with Python 3.6 or greater installed.


Download the repository

```sh
git clone https://github.com/Redislabs-Solution-Architects/ecstats2 && cd ecstats2
```

Prepare and activate the virtual environment

```sh
python3 -m venv .env && source .env/bin/activate
```

Install necessary libraries and dependencies

```sh
pip install -r requirements.txt
```

Copy the example configuration file and update its contents to match your configuration. AWS User Access Key ID and Secret Access Key are needed to access your AWS ElastiCache instances. Multiple AWS Environments (e.g Production, Staging) and AWS Regions can be defined in this file and the script will process all the AWS ElastiCache instances that are defined as separate sections in the config.ini file.

```sh
cp config.ini.example config.ini && vim config.ini
```

Execute below python command to run the script. Use -c option with configuration file if the file name is different from config.ini

```sh
python ecstats.py -c config.ini
```

When finished do not forget to deactivate the virtual environment

```sh
deactivate
```

### 2. Running the script from Docker image

**Pre-requisites:** You have Docker engine installed on your machine. Refer this link to install Docker engine: `https://docs.docker.com/engine/install/`


Download the repository

```sh
git clone https://github.com/Redislabs-Solution-Architects/ecstats2 && cd ecstats2
```

Copy the example configuration file and update its contents to match your configuration. AWS User Access Key ID and Secret Access Key are needed to access your AWS ElastiCache instances. Multiple AWS Environments (e.g Production, Staging) and AWS Regions can be defined in this file and the script will process all the AWS ElastiCache instances that are defined as separate sections in the config.ini file.

```sh
cp config.ini.example config.ini && vim config.ini
```


Execute the script using `docker run` command. Use -c option with configuration file if the file name is different from config.ini

```sh
pwd
```
For example, output of this command is `/a/path/to/ecstats`. Use the below docker command to run the script

```sh
docker run -v /a/path/to/ecstats:/app -t sumitshatwara/redis-ecstats python3 ecstats.py
```


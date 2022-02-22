# ECSTATS

TBD


## Installation

TBD

### Running the script from source

Download the repository

```
git clone https://github.com/Redislabs-Solution-Architects/ecstats2 && cd ecstats2
```

Prepare and activate the virtual environment

```
python3 -m venv .env && source .env/bin/activate
```

Install necessary libraries and dependencies

```
pip install -r requirements.txt
```

Copy the example configuration file and update its contents to match your configuration:

```
cp config.ini.example config.ini && vim config.ini
```

Execute 

```
python ecstats.py -c config.ini
```

When finished do not forget to deactivate the virtual environment

```
deactivate
```
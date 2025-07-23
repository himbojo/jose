# Environment Setup

## Create virtual environemnt
```bash
python3 -m venv .venv/
source .venv/bin/activate
```

## Install requirements
```bash
python -m pip install -r requirements.txt
```

## Install packages
```bash
python -m pip install pycryptodome
```

## Freeze requirements
```bash
python -m pip freeze > requirements.txt
```

## Exit virtual environment
```bash
deactivate
```
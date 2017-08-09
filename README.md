# Flask + EsiPy Example

This project is a small ready to work example on how to use EsiPy with Flask.

The following libraries are used:
* Flask _for the webapp part_
* [EsiPy](https://github.com/Kyria/EsiPy) _for the ESI API_
* [Flask-Login](https://flask-login.readthedocs.io/en/latest/) _for the login / session process_
* [Flask-SQLAlchemy](http://flask-sqlalchemy.pocoo.org) and [SQLAlchemy](https://www.sqlalchemy.org/) _for the database part_
* [Flask-Migrate](https://flask-migrate.readthedocs.io/en/latest/) _for the migration commands_

You will also require:
* __Virtualenv__ to setup virtualenv
* Depending on the database you want to use, the required libraries (by default this example uses SQLite, which is embedded in Python)

__Also, this example is made with Python 2.7, it might works with Python 3, but you may have to correct some lines of code__

## Get and init the project

1. Clone the repository on your system
```shell
git clone https://github.com/Kyria/flask-esipy-example.git
```

2. Create a virtualenv
```shell
cd flask-esipy-example
virtualenv venv
source venv/bin/activate
```

3. Install requirements
```shell
pip install -r requirements.txt
```

4. Setup the FLASK_APP environment variable
```shell
export FLASK_APP=app.py
```


## Create your app in https://developers.eveonline.com

1. Go to https://developers.eveonline.com
2. Login and go to `manage applications`
3. Create a new application
4. Fill all the fields

__Requirements:__
* For the scope, you will need `esi-wallet.read_character_wallet.v1` for this example
* The callback URL must be `http://<SOME_IP_OR_DOMAIN>:<SOME_PORT>/sso/callback`


## APP Configuration

1. Copy and rename the `config.dist` in `config.py`
2. Edit it.

```python
PORT = <SOME_PORT>
HOST = '<SOME_IP_OR_DOMAIN>'

SQLALCHEMY_DATABASE_URI = 'sqlite:///app.db'  # this is your database connection informations http://docs.sqlalchemy.org/en/latest/core/engines.html#database-urls

# Fill these lines with the data you get from https://developers.eveonline.com
ESI_SECRET_KEY = ''  # your secret key
ESI_CLIENT_ID = ''  # your client ID
```

## How to start everything
#### First, you will need to run the migration to create the required user table
```shell
flask db upgrade
```
> INFO  [alembic.runtime.migration] Context impl SQLiteImpl.<br>
> INFO  [alembic.runtime.migration] Will assume non-transactional DDL.<br>
> INFO  [alembic.runtime.migration] Running upgrade  -> fab636b98bc7, create_user_table


#### Run the app
```shell
python app.py
```
> * Restarting with stat<br>
> * Debugger is active!<br>
> * Debugger PIN: 206-933-487<br>
> * Running on http://localhost:5015/ (Press CTRL+C to quit)

And now you can connect to [http://localhost:5015/](http://localhost:5015/) to see it working (if you kept default configs)


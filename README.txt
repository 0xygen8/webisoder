webisoder README
==================

Getting Started
---------------

- cd <directory containing this file>

- $VENV/bin/python setup.py develop

- $VENV/bin/initialize_webisoder_db development.ini

- $VENV/bin/pserve development.ini


Running the development mail server
-----------------------------------

python -m smtpd -n -c DebuggingServer localhost:2525

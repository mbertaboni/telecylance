![Telecylance Logo](/images/telecylance.png)
# Telecylance

Another use of the Cylance API with a reckless use of Python.
Telecylance is a Telegram bot that uses Venue's API to read and notify for new threats.
You can configure it interactely using telegram and a simple sqlite db.
This is a beta version, because I'm very unfamiliar with python and even with telegram's bot.
Anyway, I think there is space to make it better.

## Disclaimer
This software is **NOT** provided or written by Cylance.
I'm not from Cylance, this code is **NOT** validated or approved by Cylance.

## Specs
- Multi-tenant Support ( only per-region at the moment )
- Waive threat per device directly from Telegram interface.
- You can run a Telegram bot that send you notification whenever a threat in Venue is found.
- You can check on Virustotal if the threat is known

## Requirements:

jwt, requests, python 2.7, sqlite3, python-telegram-bot

## Limitations:

- DB everything is in cleartext, yes I know that this is very ugly, but keep in mind that this is not intended for production use. I will fix asap.
- Support only for -euc1 tenants, otherwise you have to modify the prefix variable at line 45, but you can't mix tenants with different regions
- A lot, no proxy support
- Probably a plenty of bugs

## Setup:
First you need the tab integration in Venue and setup the API. You need the tenant id, app id and app secret.
The application need the modify permission for threats.
Then you need a token for Telegram, so ask to Botfather https://telegram.me/botfather for a /newbot.
Choose a serious name and botfather will give you a unique Token. Otherwise in /mybots you can ask for the token.
Insert the Token at the line 44 of telecylance.py.
Switch to Telegram and setup everything using command /setup

## HowTo

Once the bot is started you can configure it this way

    /setup XXXXXXXX-XXXX-XXXX-XXXX-XXXXXXXXXXXXX YYYYYYYY-YYYY-YYYY-YYYY-YYYYYYYYYYYY ZZZZZZZZ-ZZZZ-ZZZZ-ZZZZ-ZZZZZZZZZZZZ -euc1 Tenant_friendly_name

if you need to setup other tenants you can call /setup and follow the interactive setup

![Telecylance Logo](/images/setup.png)
Then you have to set a timer time expressed in seconds. This is the amount of time that Telecylance will use between requests to Venue for new threats.

    /set 30

Every 30 seconds Telecylance will ask to different tenants for new threats and, if a new threat is catch in the last 5 minutes Telecylance will notify the threat found only ONCE.
Keep in mind that the waive action is logged in the Log of Venue but without IP or name.

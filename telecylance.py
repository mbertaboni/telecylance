#!/usr/bin/env python
#
# telecylance - Telegram Cylance Bot - https://github.com/mbertaboni/telecylance
# Copyright (C) 2018 Maurizio Bertaboni
# LOOK DOWN for SETUP !
# Telegram Cylance Bot (this file) is free software: you can redistribute it and/or modify
# it under the terms of the GNU Affero General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# any later version.
#
# Telegram Cylance Bot (this file) is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU Affero General Public License for more details.
#
# You should have received a copy of the GNU Affero General Public License
# If not, see <http://www.gnu.org/licenses/>.
#
import jwt  # PyJWT version 1.5.3 as of the time of authoring.
import uuid
import requests  # requests version 2.18.4 as of the time of authoring.
import json
import sys
import argparse
import collections
import urllib2
import socket
import sqlite3
import re
from datetime import datetime, timedelta
from dateutil import tz
from telegram import InlineKeyboardButton, InlineKeyboardMarkup
from telegram import KeyboardButton, ReplyKeyboardMarkup, ReplyKeyboardRemove
from telegram.ext import Updater, CommandHandler, MessageHandler, Filters, CallbackQueryHandler, ConversationHandler, RegexHandler
import logging

# Enable logging
logging.basicConfig(format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
                    level=logging.INFO)

logger = logging.getLogger(__name__)
# ********************************** START SETUP

token = ""
prefix = "-euc1"

# ********************************** END SETUP
updater = Updater(token)


AUTH_URL = "https://protectapi" + prefix + ".cylance.com/auth/v2/token"
CHOOSING, WAIVE = range(2)


def regular_choice(bot, update, user_data):
    text = update.message.text
    user_data['choice'] = text
    if user_data['choice'] == 'Yes':
        update.message.reply_text(
            'Ok "%s"? So, I will reconfigure everything for you. Now re-type /setup with new arguments')
        conn = sqlite3.connect('telecylance.db')
        truncate = conn.execute("DELETE FROM conf")
        vacuum = conn.execute("VACUUM")
        update.message.reply_text(
            'Usage: /setup <tenant_id> <app_id> <app_secret> <prefix> <name>')

        # reset database
    elif user_data['choice'] == 'Add':
        update.message.reply_text(
            'Ok, you want to add another tenant so..re-type /setup with new arguments')
        conn = sqlite3.connect('telecylance.db')
        conn.execute("INSERT INTO conf (ten_id,app_id,app_secret,prefix,ok,name) VALUES (?,?,?,?,?,?)",
                     ("new", "new", "new", "new", 1, "new"))
        conn.commit()
        conn.close()
        update.message.reply_text(
            'Usage: /setup <tenant_id> <app_id> <app_secret> <prefix> <name>')
    else:
        update.message.reply_text('Ok, I will do nothing')


def help(bot, update):
    """Send a message when the command /help is issued."""
    update.message.reply_text(
        'Hello, this is TeleCylance Bot! \nYou can send me these commands:')
    update.message.reply_text(
        '/set [seconds] : this will set the number of seconds between checks in Venue')
    update.message.reply_text(
        '/unset : this will unset the continuos checks in Venue')
    update.message.reply_text(
        '/setup : this will setup the communication between Venue and TeleCylance (Usage: /setup <tenant_id> <app_id> <app_secret> <prefix> <name>)')


def check_setup(bot, update):
    if tid_val == "" or app_id == "" or app_secret == "":
        update.message.reply_text(
            "Hey ! - you must configure TeleCylance Bot in order to run...")


def setup_is_ok():

    db = sqlite3.connect('telecylance.db')
    cur = db.cursor()
    cur.execute("SELECT * from conf WHERE ok=0 OR name='new'")
    rows = cur.fetchall()
    if len(rows) > 0:
        return 0
    else:
        return 1
    db.close()


def setup(bot, update, args, job_queue, chat_data):
    chat_id = update.message.chat_id
    try:
        if not setup_is_ok():
            conn = sqlite3.connect('telecylance.db')
            tenant_id = str(args[0])
            app_id = str(args[1])
            app_secret = str(args[2])
            prefix = str(args[3])
            name = str(args[4])
            if tenant_id < 0:
                update.message.reply_text('Sorry you must specify a tenant id')
                return
            if app_id < 0:
                update.message.reply_text('Sorry you must specify an app id')
                return
            if app_secret < 0:
                update.message.reply_text(
                    'Sorry you must specify the app secret')
                return update.message.reply_text('Timer successfully set!')
            if prefix < 0:
                update.message.reply_text(
                    'Sorry you must specify a prefix (-NA/-USgov/-euc1)')
                return
            if name < 0:
                update.message.reply_text(
                    'Sorry you must specify a friendly name for this tenant')
                return
            conn.execute(
                "INSERT INTO conf (ten_id,app_id,app_secret,prefix,ok,name) VALUES (?,?,?,?,?,?)", (tenant_id, app_id, app_secret, prefix, 1, name))
            conn.execute("DELETE FROM conf WHERE name='new'")
            conn.commit()
            update.message.reply_text('Setup ready')
            conn.close()
        else:
            reply_keyboard = [['Yes', 'No', 'Add']]
            markup = ReplyKeyboardMarkup(
                reply_keyboard, one_time_keyboard=True)
            bot.sendChatAction(chat_id, "TYPING")

            update.message.reply_text(
                'Setup already present, Do you want to re-configure everything or add another tenant ?', reply_markup=markup)
            return CHOOSING

    except (IndexError, ValueError):
        update.message.reply_text(
            'Usage: /setup <tenant_id> <app_id> <app_secret> <prefix> <name>')


def call_handler(bot, update):
    if update.callback_query.data == 'please_waive_me':
        bot.answerCallbackQuery(callback_query_id=update.callback_query.id,
                                text="Waiving Threat...")
        message = update.callback_query.message.text
        device_id_raw = re.search('\[(.*)\]', message)
        tid_val_raw = re.search('\{(.*)\}', message)
        threat_sha = re.search('SHA256:(.*)', message)
        tid_val = tid_val_raw.group(1).strip()
        threat_id = threat_sha.group(1).strip()
        device_id = device_id_raw.group(1).strip()
        print tid_val
        print device_id
        # ho bisogno di leggere da che tenant arriva sta cosa
        db = sqlite3.connect('telecylance.db')
        cur = db.cursor()
        cur.execute("SELECT * from conf WHERE ten_id=?", (tid_val,))
        rows = cur.fetchall()
        print rows
        for tenant in rows:
            app_id = tenant[1]
            app_secret = tenant[2]
        db.close()

        get_token(app_id, tid_val, app_secret)
        the_url = "https://protectapi" + prefix + \
            ".cylance.com/devices/v2/" + device_id + "/threats"

        payload = {"threat_id": threat_id, "event": "Waive"}
        headers = headers_request
        resp = requests.post(the_url, headers=headers,
                             data=json.dumps(payload))
        bot.sendMessage(update.callback_query.message.chat.id,
                        "Threat Waived", parse_mode='HTML', disable_web_page_preview=0)

    if update.callback_query.data == 'check_on_vt':
        bot.answerCallbackQuery(callback_query_id=update.callback_query.id,
                                text="Let's go to VT...")
        message = update.callback_query.message.text
        threat_sha = re.search('SHA256:(.*)', message)
        threat_id = threat_sha.group(1).strip()

        the_url = "Virus Total thinks this " + "https://www.virustotal.com/en/file/" + \
            threat_id + "/analysis/"
        bot.sendMessage(update.callback_query.message.chat.id,
                        the_url, parse_mode='HTML', disable_web_page_preview=0)


def error(bot, update, error):
    logger.warning('Update "%s" caused error "%s"', update, error)


def build_url(object_type, page_number, page_size, hash="?"):
    if hash != '?':
        the_url = "https://protectapi" + prefix + ".cylance.com/" + object_type + \
            "/v2/" + hash + "/devices?page=" + str(page_number) + \
            "&page_size=" + str(page_size)
    else:
        the_url = "https://protectapi" + prefix + ".cylance.com/" + object_type + \
            "/v2/" + hash + "page=" + str(page_number) + \
            "&page_size=" + str(page_size)
    return the_url


def get_threats(bot, job):
    # Ready to be multi-tenant ?
    db = sqlite3.connect('telecylance.db')
    cur = db.cursor()
    cur.execute(
        "SELECT * FROM conf where ok=1")
    rows = cur.fetchall()
    for tenant in rows:
        print tenant
        tid_val = tenant[0]
        app_id = tenant[1]
        app_secret = tenant[2]
        tenant_name = tenant[5]
        access_token = get_token(app_id, tid_val, app_secret)
        if setup_is_ok():
            print "ok"
            tot = 0
            detail_request = requests.get(
                build_url('threats', 1, 200), headers=headers_request)
            number_elements = json.loads(detail_request.text)
            total_pages = int(number_elements['total_pages'])
            total_pages = total_pages + 1
            # total_number_of_items = number_elements['total_number_of_items']
            print "\n\r"
            for page in range(1, total_pages):
                threats = requests.get(build_url('threats', int(page), 200),
                                       headers=headers_request)
                threats_detail = json.loads(threats.text)
            #    print page
                #print threats_detail
                for threat in threats_detail['page_items']:
                    lastfound_date = threat['last_found']
                    utc = tz.tzutc()
                    local_zone = tz.tzlocal()
                    lastfound_utc = datetime.strptime(
                        lastfound_date, '%Y-%m-%dT%H:%M:%S')
                    lastfound_utc = lastfound_utc.replace(tzinfo=utc)
                    lastfound_zone = lastfound_utc.astimezone(local_zone)
                    lastfound_zone = lastfound_zone.replace(tzinfo=None)
                    lastfound_zone_string = lastfound_zone.strftime(
                        '%Y-%m-%d %H:%M:%S')

                    startdate_raw = datetime.now()
                    startdate_raw = startdate_raw + timedelta(minutes=-60)
                    startdate = startdate_raw.strftime('%Y-%m-%d %H:%M:%S')
                    startdate_obj = datetime.strptime(
                        startdate, '%Y-%m-%d %H:%M:%S')

                    #print "Request in corso.." + threat['name']
                    #print "Last Found" + lastfound_zone_string
                    #print "Startdate" + startdate
                    if lastfound_zone > startdate_obj:
                        print "Trovata Roba"
                        unique_threat = str(threat['sha256'])
                        db = sqlite3.connect('telecylance.db')
                        cur = db.cursor()
                        cur.execute(
                            "SELECT threat_id FROM temp_data where threat_id=? and tenant_id=?", (unique_threat, tid_val))
                        rows = cur.fetchall()
                        if len(rows) > 0:
                            display_message = 0
                        else:
                            display_message = 1
                        db.commit()

                        if display_message == 1:
                            message_telegram = "<b>Found new malware !</b>" + "\n"
                            message_telegram += "<b>TENANT: </b>" + tenant_name + \
                                " {" + tid_val + "} " + "\n"
                            message_telegram += "<b>Threat name:</b> " + \
                                threat['name'] + "\n" + "<b>Found on: </b>" + \
                                lastfound_zone.strftime(
                                    "%Y-%m-%d %H:%M:%S") + "\n"
                            str_ip = ""
                            threat_drilldown = requests.get(build_url('threats', 1, 200, threat['sha256']),
                                                            headers=headers_request)
                            threat_drilldown_detail = json.loads(
                                threat_drilldown.text)
                            for dettagli in threat_drilldown_detail['page_items']:
                                for ip in dettagli['ip_addresses']:
                                    str_ip += ip + ","
                                message_telegram += "<b>Device Affected: </b>" + \
                                    dettagli["name"] + " [" + dettagli["id"] + "] " + \
                                    " (" + str_ip[:-1] + ")" + "\n"
                                message_telegram += "<b>File Path: </b>" + \
                                    dettagli["file_path"] + "\n"
                                message_telegram += "<b>SHA256: </b>" + \
                                    threat['sha256'] + "\n"
                                unique_date = str(datetime.fromtimestamp)
                                waive_keyboard = InlineKeyboardButton(
                                    text="Waive!", callback_data="please_waive_me")

                                check_on_vt_keyboard = InlineKeyboardButton(
                                    text="Check on VT", callback_data="check_on_vt")
                                custom_keyboard = [
                                    [waive_keyboard], [check_on_vt_keyboard]]
                                reply_markup = InlineKeyboardMarkup(
                                    custom_keyboard)
                                # devo segnarmi che ho buttato fuori un messaggio
                                # cosi' non esco piu' con un secondo messaggio
                                conn = sqlite3.connect('telecylance.db')
                                conn.execute(
                                    "INSERT INTO temp_data (threat_id,timestamp,tenant_id) VALUES (?,?,?)", (unique_threat, unique_date, tid_val))
                                conn.commit()
                                bot.sendMessage(job.context, text=message_telegram,
                                                parse_mode='HTML', disable_web_page_preview=1, reply_markup=reply_markup)
        else:
            bot.sendMessage(
                job.context, text="setup not present, use /setup to configure TeleCylance")
            job.schedule_removal()


def get_token(app_id, tid_val, app_secret):
    timeout = 1800
    now = datetime.utcnow()
    timeout_datetime = now + timedelta(seconds=timeout)
    epoch_time = int((now - datetime(1970, 1, 1)).total_seconds())
    epoch_timeout = int(
        (timeout_datetime - datetime(1970, 1, 1)).total_seconds())
    jti_val = str(uuid.uuid4())
    claims = {
        "exp": epoch_timeout,
        "iat": epoch_time,
        "iss": "http://cylance.com",
        "sub": app_id,
        "tid": tid_val,
        "jti": jti_val
    }
    encoded = jwt.encode(claims, app_secret, algorithm='HS256')
    payload = {"auth_token": encoded}
    headers = {"Content-Type": "application/json; charset=utf-8"}
    resp = requests.post(AUTH_URL, headers=headers,
                         data=json.dumps(payload))
    access_token = json.loads(resp.text)['access_token']
    global headers_request
    headers_request = {"Accept": "application/json",
                       "Authorization": "Bearer " + access_token,
                       "Content-Type": "application/json"}
    return access_token


def set_timer(bot, update, args, job_queue, chat_data):

    chat_id = update.message.chat_id
    try:
        # args[0] should contain the time for the timer in seconds
        due = int(args[0])
        if due < 0:
            update.message.reply_text('Sorry we can not go back to future!')
            return

        # Add job to queue
        job = job_queue.run_repeating(
            get_threats, due, context=chat_id)
        chat_data['job'] = job

        update.message.reply_text('Timer successfully set!')

    except (IndexError, ValueError):
        update.message.reply_text('Usage: /set <seconds>')


def unset(bot, update, chat_data):
    if 'job' not in chat_data:
        update.message.reply_text('You have no active timer')
        return

    job = chat_data['job']
    job.schedule_removal()
    del chat_data['job']
    update.message.reply_text('Timer successfully unset!')


def main():

    # Get the dispatcher to register handlers
    dp = updater.dispatcher

    conv_handler = ConversationHandler(
        entry_points=[CommandHandler('setup', setup, pass_args=True,
                                     pass_job_queue=True, pass_chat_data=True)],
        states={
            CHOOSING: [RegexHandler('^(Yes|No|Add)$',
                                    regular_choice,
                                    pass_user_data=True)
                       ]
        },
        fallbacks=[CommandHandler('setup', setup, pass_args=True,
                                  pass_job_queue=True, pass_chat_data=True)]
    )

    dp.add_handler(conv_handler)
    # on different commands - answer in Telegram
    dp.add_handler(CommandHandler("setup", setup, pass_args=True,
                                  pass_job_queue=True, pass_chat_data=True))
    dp.add_handler(CommandHandler("help", help))
    dp.add_handler(CommandHandler("set", set_timer,
                                  pass_args=True,
                                  pass_job_queue=True, pass_chat_data=True))
    dp.add_handler(CommandHandler("unset", unset, pass_chat_data=True))
    dp.add_handler(CommandHandler("malware", get_threats, pass_chat_data=True))
    dp.add_handler(CallbackQueryHandler(call_handler))

    # log all errors
    dp.add_error_handler(error)

    # Start the Bot
    updater.start_polling()

    sys.exit(0)

    # Run the bot until you press Ctrl-C or the process receives SIGINT,
    # SIGTERM or SIGABRT. This should be used most of the time, since
    # start_polling() is non-blocking and will stop the bot gracefully.
    updater.idle()


if __name__ == '__main__':
    main()

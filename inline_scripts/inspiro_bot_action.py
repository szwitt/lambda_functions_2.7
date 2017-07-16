# inspiro_bot_action.py

import boto3
import httplib
import json
import logging
import os
import time
import decimal
from base64 import b64decode
from urlparse import parse_qs, urlparse


# decrypting the key passed thru the gateway from slack
encrypted_slackKey = os.environ['slackKey']
expected_token = boto3.client('kms').decrypt(CiphertextBlob=b64decode(encrypted_slackKey))['Plaintext']

encrypted_slackLegacyToken = os.environ['slackLegacyToken']
slackLegacyToken = boto3.client('kms').decrypt(CiphertextBlob=b64decode(encrypted_slackLegacyToken))['Plaintext']


# setup logging
logger = logging.getLogger()
logger.setLevel(logging.DEBUG)


# Immediate Responder to the users request - not visible to all
def respond():
    return {
        'statusCode': '200',
        'headers': {
            'Content-Type': 'application/json',
        },
    }


# defining the function that will call inspirobot.me
def get_inspiration():
    headers = {'cache-control': 'no-cache'}
    conn = httplib.HTTPConnection("inspirobot.me")
    conn.request("GET", "/api?generate=true", headers=headers)
    response = conn.getresponse()
    inspiration_response = response.read()
    return inspiration_response


#  Post inspiration to Slack
def post_to_slack(slack_payload, ser_name, conversation_url):
    payload = ('%s') % slack_payload
    headers = {
        'content-type': "application/json",
        'cache-control': "no-cache"
    }
    parsed_url = urlparse(conversation_url)
    conn = httplib.HTTPSConnection(parsed_url.netloc)
    conn.request("POST", parsed_url.path, payload, headers)
    response = conn.getresponse()

    logger.info(response.status)
    logger.info(response.reason)


# defining the function that will handle the incoming slack request
def incoming_lambda_handler(event, context):
    params = parse_qs(event['body'])
    token = params['token'][0]
    if token != expected_token:
        logger.error("Request token (%s) does not match expected", token)
        return respond(Exception('Invalid request token'))


    original_message = params['original_message'][0]
    button_select = params['actions']['value'][0]
    channel_id = params['channel_id'][0]
    conversation_url = params['response_url'][0]
    message_ts = params['message_ts'][0]


    if button_select == 'publish': # change response_type == in_channel
        slack_payload =
        update_response_type = original_message
        post_to_slack(slack_payload, conversation_url, message_ts)

    elif button_select == 'shuffle': # call get_inspiration response new_image_url
        slack_payload =
        new_inspiration_link = get_inspiration()
        post_to_slack(slack_payload, conversation_url, message_ts)
        # replace_original = true

    elif button_select == 'cancel':
        slack_payload =
        # delete_original = true
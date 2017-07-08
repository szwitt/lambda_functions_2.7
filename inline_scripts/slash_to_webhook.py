import httplib, urllib
import json
import logging
import os
from base64 import b64decode

import boto3

logger = logging.getLogger()
logger.setLevel(logging.INFO)

eapp_uuid = os.environ['app_uuid']
app_uuid = boto3.client('kms').decrypt(CiphertextBlob=b64decode(eapp_uuid))['Plaintext']

ebearer_token = os.environ['bearer_token']
bearer_token = boto3.client('kms').decrypt(CiphertextBlob=b64decode(ebearer_token))['Plaintext']

user_id = 'userId'
user_name = 'display_name'
conversation_uuid = 'xxx'

params = ("{\"sender_id\":\"layer:///identities/%s\",\"parts\":[{\"body\":\"%s - Requested assistance thru Button :)\","
          "\"mime_type\":\"text/plain\"}]}" % (user_id, user_name))

headers = {
    'accept': "application/vnd.layer+json; version=2.0",
    'authorization': bearer_token,
    'content-type': "application/json",
    'cache-control': "no-cache"
    }


def lambda_handler(event, context):

    logging.info('Received event: ' + json.dumps(event))
    conn = httplib.HTTPSConnection("api.layer.com")
    conn.request("POST", "/apps/%s/conversations/%s/messages" % (app_uuid, conversation_uuid), params, headers)
    response = conn.getresponse()

    logger.info(response.status)
    logger.info(response.reason)

    data = response.read()
    logger.info(data.decode("utf-8"))

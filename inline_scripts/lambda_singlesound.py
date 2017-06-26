import boto3
import json
import logging
# import slackweb

from base64 import b64decode
from urlparse import parse_qs


ENCRYPTED_EXPECTED_TOKEN = 'xxxxxx'  # Enter the base-64 encoded, encrypted Slack command token (CiphertextBlob)

kms = boto3.client('kms')
client = boto3.client('iot-data', region_name='us-west-2')

expected_token = kms.decrypt(CiphertextBlob=b64decode(ENCRYPTED_EXPECTED_TOKEN))['Plaintext']

logger = logging.getLogger()
logger.setLevel(logging.INFO)


def respond(err, res=None):
    return {
        'statusCode': '400' if err else '200',
        'body': err.message if err else json.dumps(res),
        'headers': {
            'Content-Type': 'application/json',
        },
    }


def lambda_handler(event, context):

    response = client.publish(
        topic='$aws/things/piTractor/shadow/update',
        qos=1,
        payload=json.dumps({"state": {"desired": {"function": "woohoo" ""}}})
    )

import boto3
import decimal
import time


# The boto3 dynamoDB resource
dynamodb = boto3.resource('dynamodb',
                          aws_session_token='xxx'
                          aws_access_key_id='xxx',
                          aws_secret_access_key='xxx',
                          region_name='us-west-2')


def get_dynamo_last_run(requesting_channel):
    current_epoch = int(time.time())
    table = dynamodb.Table('inspirobot')
    response = table.get_item(Key={"channel": requesting_channel})
    if 'Item' not in response:
        response = table.put_item(
            Item={
                'channel': requesting_channel,
                'lastRun': current_epoch
            }
        )
        print "New item created"
        return False



    last_run = response['Item']['lastRun']
    if last_run > (current_epoch - 60):
        print last_run
        return True
    else:
        response = table.update_item(
            Key={
                'channel': requesting_channel
            },
            UpdateExpression="set lastRun = :e",
            ExpressionAttributeValues={
                ':e': decimal.Decimal(current_epoch)
            },
            ReturnValues="UPDATED_NEW"
        )
        print response
        return False

value = get_dynamo_last_run('seattle-chatter3')
print value

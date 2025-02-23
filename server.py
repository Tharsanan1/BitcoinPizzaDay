import json
import boto3
import hashlib
from datetime import datetime
import logging
from decimal import Decimal

class DecimalEncoder(json.JSONEncoder):
  def default(self, obj):
    if isinstance(obj, Decimal):
      return str(obj)
    return json.JSONEncoder.default(self, obj)

# Set up logging
logger = logging.getLogger()
logger.setLevel(logging.INFO)

# Initialize DynamoDB client
dynamodb = boto3.resource('dynamodb')
table = dynamodb.Table('Submissions')

def lambda_handler(event, context):
    # Log the incoming event
    logger.info(f"Received event: {json.dumps(event)}")
    
    # Handle POST request for submissions
    if event['httpMethod'] == 'POST' and event['path'] == '/submit':
        try:
            body = json.loads(event['body'])
            email = body.get('email')
            nonce = int(body.get('nonce', 0))

            logger.info(f"Processing submission for email: {email}, nonce: {nonce}")

            if not email or not isinstance(nonce, int) or nonce < 0:
                logger.warning("Validation failed: Missing or invalid email/nonce")
                return {
                    'statusCode': 400,
                    'body': json.dumps({'error': 'Email and positive nonce are required'})
                }

            # Check for duplicates
            response = table.query(
                KeyConditionExpression='email = :e AND nonce = :n',
                ExpressionAttributeValues={':e': email, ':n': nonce}
            )
            if response['Items']:
                logger.warning(f"Duplicate submission detected for email: {email}, nonce: {nonce}")
                return {
                    'statusCode': 400,
                    'body': json.dumps({'error': 'This email and nonce combination has already been submitted'})
                }

            # Calculate SHA-256 and leading zeros
            combined = f"{email}{nonce}"
            hash_obj = hashlib.sha256(combined.encode())
            hash_hex = hash_obj.hexdigest()
            hash_binary = ''.join(format(byte, '08b') for byte in hash_obj.digest())
            leading_zeros = 0
            for bit in hash_binary:
                if bit == '0':
                    leading_zeros += 1
                else:
                    break

            # Store in DynamoDB
            table.put_item(
                Item={
                    'email': email,
                    'nonce': nonce,
                    'leading_zeros': leading_zeros,
                    'timestamp': datetime.now().isoformat()
                }
            )

            logger.info(f"Successfully stored submission - email: {email}, leading_zeros: {leading_zeros}")
            return {
                'statusCode': 201,
                'body': json.dumps({'message': 'Submission successfully added', 'leading_zeros': leading_zeros})
            }

        except Exception as e:
            logger.error(f"Error processing POST request: {str(e)}")
            return {
                'statusCode': 500,
                'body': json.dumps({'error': str(e)})
            }

    # Handle GET request for leaderboard
    elif event['httpMethod'] == 'GET' and event['path'] == '/leaderboard':
        try:
            logger.info("Fetching leaderboard")
            response = table.scan(
                AttributesToGet=['email', 'nonce', 'leading_zeros', 'timestamp']
            )
            submissions = response['Items']

            # Anonymize emails
            anonymized_submissions = [
                {
                    'email': f"{sub['email'][0]}***@{sub['email'].split('@')[1]}" if '@' in sub['email'] else sub['email'],
                    'nonce': sub['nonce'],
                    'leading_zeros': sub['leading_zeros'],
                    'timestamp': sub['timestamp']
                }
                for sub in submissions
            ]

            # Sort by leading_zeros in descending order
            anonymized_submissions.sort(key=lambda x: (-x['leading_zeros'], x['timestamp']))
            anonymized_submissions = anonymized_submissions[:10]
            logger.info(f"Anonymized submissions: {anonymized_submissions}")
            logger.info(f"Returning leaderboard with {len(anonymized_submissions)} entries")
            return {
                'statusCode': 200,
                'body': json.dumps(anonymized_submissions, cls=DecimalEncoder)
            }

        except Exception as e:
            logger.error(f"Error processing GET request: {str(e)}")
            return {
                'statusCode': 500,
                'body': json.dumps({'error': str(e)})
            }

    logger.warning(f"Unhandled request: method={event['httpMethod']}, path={event['path']}")
    return {
        'statusCode': 404,
        'body': json.dumps({'error': 'Not Found'})
    }
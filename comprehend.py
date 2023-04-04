"""
Redact PHI/PII data using AWS comprehend:
We can redact thr PHI/PII in ad-hoc basis when ever we want using Comprehend API's
read more about comprehend API - https://boto3.amazonaws.com/v1/documentation/api/latest/reference/services/comprehend.html

We are giving some input data contains sensitive informationa and redacting/masking by replacing the found entities
with xxxx
"""
import boto3


def redact_phi(input_text):
    # Client declaration
    comprehend = boto3.client('comprehend', region_name='us-west-2')
    # Call the Comprehend DetectEntities API to detect PHI entities
    entities = comprehend.detect_entities(Text=input_text, LanguageCode='en')
    # It finds the PHI/PII entities listed in https://docs.aws.amazon.com/comprehend/latest/dg/realtime-pii-console.html
    # it won't redact the value directly, so we're replacing the findings with string 'x'
    print(entities)  # Debugging statement

    for entity in entities['Entities']:
        str_length = len(entity['Text'])
        input_text = input_text.replace(entity['Text'], 'x' * str_length)
    return input_text


# Example usage:
input_text = "John Smith's phone number is (555) 555-5555 and his address is 123 Main St and his DOB 15/04/1995."
redacted_text = redact_phi(input_text)
print(redacted_text)

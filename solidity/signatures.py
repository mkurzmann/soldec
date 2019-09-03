import requests
import json
import logging
import csv


def get_function_signature_from_4bytes(hex_signature):
    """
    Requests the function signature from 4byte-directory based on the hex_signature to get the text_signature
    if the setting for extracting the signatures is enabled

    Args:
      hex_signature: the signature of the function as hex value

    Returns:
      signature of the function as text
    """

    resp = requests.get('https://www.4byte.directory/api/v1/signatures/?hex_signature=' + hex_signature)
    if resp.status_code != 200:
        # This means something went wrong.
        logging.error("something went wrong at 4byte-directory api call" + str(resp.status_code))
        return hex_signature

    json_data = json.loads(resp.text)
    for sig in json_data['results']:
        logging.info("got function signature: " + sig['text_signature'])
        return sig['text_signature']

    return hex_signature


def get_function_signature(hex_signature):
    """
    Requests the function signature from the CSV file based on the hex_signature to get the text_signature
    if the setting for extracting the signatures is enabled

    Args:
      hex_signature: the 4-byte signature of the function as hex value

    Returns:
      signature of the function as text
    """

    # read csv, and split on ";" the line
    csv_file = csv.reader(open('data/fourbytes.csv', "r"), delimiter=";")

    # loop through csv list
    for row in csv_file:
        # if current rows 2nd value is equal to hex signature, function signature found

        if row[1][2:] == hex_signature[2:]:
            logging.info("got function signature: " + row[0])
            return row[0]

    return hex_signature


def get_event_signature(hex_signature):
    """
    Requests the event signature from the CSV file based on the hex_signature to get the text_signature
    if the setting for extracting the signatures is enabled

    Args:
      hex_signature: the 32-byte signature of the event as hex value

    Returns:
      signature of the event as text
    """

    # read csv, and split on ";" the line
    csv_file = csv.reader(open('data/event.csv', "r"), delimiter=";")

    # loop through csv list
    for row in csv_file:
        # if current rows 2nd value is equal to hex signature, function signature found

        if row[1][2:] == hex_signature[2:]:
            logging.info("got event signature: " + row[0])
            return row[0]

    return hex_signature

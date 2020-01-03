import requests
import json
import logging
import csv


def get_function_signature_from_4bytes(hex_signature):
    """
    Requests the function signature from 4byte-directory based on the hex_signature to get the text_signature

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

    Args:
      hex_signature: the 4-byte signature of the function as hex value (a string starting with 0x)

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

    # hex_signature is returned if no text signature was found in the csv file
    return hex_signature


def get_function_signature_with_args(hex_signature):
    """
    Requests the function signature from the CSV file based on the hex_signature
    including ongoing names for the parameters

    Args:
      hex_signature: the 4-byte signature of the function as hex value

    Returns:
      signature of the function as text including parameter names
    """
    signature = get_function_signature(hex_signature)

    if not signature.__contains__("(") or signature.__contains__("()"):
        # no signature found or signature does not have parameters
        return signature
    elif not signature.__contains__(","):
        # function has exactly one argument
        signature = signature.replace(")", " _args1)")
    else:
        # function has more than one arguments
        parts = signature[0:-1].split(",")
        signature = ""
        for i, p in enumerate(parts):
            signature += p + " _args" + str(i + 1) + ", "
        signature = signature[0:-2] + ")"

    return signature


def get_event_signature(hex_signature):
    """
    Requests the event signature from the CSV file based on the hex_signature to get the text_signature

    Args:
      hex_signature: the 32-byte signature of the event as hex value (a string starting with 0x)

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

    # hex_signature is returned if no text signature was found in the csv file
    return hex_signature


def get_event_signature_with_args(hex_signature, args):
    """
    Requests the event signature from the CSV file based on the hex_signature
    including ongoing names for the parameters

    Args:
      hex_signature: the 32-byte signature of the event as hex value
      args: the names of the parameters of the event

    Returns:
      signature of the event as text including parameter names and parameter types as comments
    """

    signature = get_event_signature(hex_signature)

    if not signature.__contains__("(") or signature.__contains__("()"):
        # no signature found or signature does not have parameters
        return signature
    elif not signature.__contains__(",") and args:
        # event has exactly one argument
        parts = signature.split("(")
        signature = parts[0] + "(/*" + parts[1][:-1] + "*/ " + args[0] + ")"
    else:
        # event has more than one argument
        parts = signature[:-1].split("(")
        parts_final = [parts[0] + "("]
        for p in parts[1].split(","):
            parts_final.append(p)
        signature = parts_final[0]
        for i, p in enumerate(parts_final[1:]):
            if len(args) > i:
                signature += "/*" + p + "*/ " + args[i] + ", "
            else:
                signature += p + ", "
        signature = signature[0:-2] + ")"

    return signature

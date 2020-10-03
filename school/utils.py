from rest_framework.response import Response
from rest_framework import status
# from .models import Pincode, SalaryDate, DailyAttendence
import datetime


def response(data, code=status.HTTP_200_OK, error="",headers=None):
    """
    Overrides rest_framework response

    :param data: data to be send in response
    :param code: response status code(default has been set to 200)
    :param error: error message(if any, not compulsory)

    """
    res = {"status_code": code, "error": error, "response": data}
    return Response(data=res, status=status.HTTP_200_OK,headers=headers)

def create_error_message(error_dict):
    """
    Changes a dict of errors into a string
    :param error_dict:a dictionary of errors
    :return:a string made of errors
    """
    error_string = ''
    for error in error_dict:
        error_string += error_dict[error] + ". "
    return error_string


def generate_error_message(errors):
    """
    :param errors:
    :return: Returns a string used to send directly as error message.
    """
    error_message = ""
    for key, value in errors.items():
        error_message = key.replace("_", " ").title() + " : " + error_message + " " + str(" ".join(value)) + ", "
    return error_message[:-2]

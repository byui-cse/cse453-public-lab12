########################################################################
# Program:
#    Lab 12, Bell-LaPadula
# Author:
#    Br. Helfrich, Kyle Mueller, Martin Melerio, Andersen Stewart, Abel Wenning
# Summary: 
#    This program is designed to keep track of a number of secret
#    messages. IT will display messages to the appropriate users
#    and withhold messages from those lacking the authority.
########################################################################

from os import path
from getpass import getpass
import interact, messages

# Gets the absolute path of the "messages.txt" file
FILE_NAME = path.join(path.dirname(path.abspath(__file__)), "messages.txt")

session_open = True

def close_session():
    global session_open
    session_open = False

def open_session():
    global session_open
    session_open = True

################################################
# DISPLAY OPTIONS
################################################
def display_options():
    print("\td .. Display the list of messages\n" +
          "\ts .. Show one message\n" +
          "\ta .. Add a new message\n" + 
          "\tu .. Update an existing message\n" + 
          "\tr .. Delete an existing message\n" + 
          "\to .. Display this list of options\n" + 
          "\tl .. Log out\n")

################################################
# SIMPLE PROMPT
################################################
def simple_prompt(prompt):
    return input(prompt)

####################################################
# SESSION
# One login session
####################################################
def session(messages):
    open_session()

    print("Users:")
    interact.display_users()
    username = simple_prompt("\nWhat is your username? ")
    if interact.Interact._id_from_user(None, username) == -1:
        print(f"Welcome, {username}.  You are a guest user with Public security clearance.\n")
        password = None
    else:
        password = getpass("What is your password? ")

    interact_ = interact.Interact(username, password, messages)
    if not hasattr(interact_, "_control"):
        # Interact not instantiated because user is not a guest, and
        # was not authenticated
        return

    print(f"\nWelcome, {username}. Please select an option:\n")
    display_options()

    options = {
        "o": "print('Options:'); display_options();",
        "d": "interact_.display();",
        "s": "interact_.show();",
        "a": "interact_.add();",
        "u": "interact_.update();",
        "r": "interact_.remove();",
        "l": "print(f'Goodbye, {username}{chr(10)}'); close_session();"
    }

    while session_open:
        option = input(f"{username}> ")
        exec(options.get(option, "print(f\"Unknown option: \'{option}\'\");"))

####################################################
# MAIN
# Where it all begins and where it all ends
####################################################
def main():
    messages_ = messages.Messages(FILE_NAME)

    done = False
    while not done:
        session(messages_)
        done = input("Will another user be logging in? (y/n) ").upper() != "Y"

    return 0

if __name__ == "__main__":
    main()

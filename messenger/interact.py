########################################################################
# COMPONENT:
#    INTERACT
# Author:
#    Br. Helfrich, Kyle Mueller, Martin Melerio, Andersen Stewart, Abel Wenning
# Summary: 
#    This class allows one user to interact with the system
########################################################################

import control

###############################################################
# USER
# User has a name and a password
###############################################################
class User:
    def __init__(self, name, password, control):
        self.name = name
        self.password = password
        self.control = control

userlist = [
   [ "AdmiralAbe",     "password",  control.Control.Secret ],  
   [ "CaptainCharlie", "password",  control.Control.Privileged ], 
   [ "SeamanSam",      "password",  control.Control.Confidential ],
   [ "SeamanSue",      "password",  control.Control.Confidential ],
   [ "SeamanSly",      "password",  control.Control.Confidential ]
]

###############################################################
# USERS
# All the users currently in the system
###############################################################
users = [*map(lambda u: User(*u), userlist)]

ID_INVALID = -1

######################################################
# INTERACT
# One user interacting with the system
######################################################
class Interact:

    ##################################################
    # INTERACT CONSTRUCTOR
    # Authenticate the user and get him/her all set up
    ##################################################
    def __init__(self, username, password, messages):
        if password != None:
            # not a guest user, so validate password
            if not self._authenticate(username, password):
                print("ERROR! That username and password combination is not valid\n")
                return

        id_ = self._id_from_user(username)
        self._username = username
        self._control = (
            control.Control.Public
            if id_ == -1
            else users[id_].control)
        self._p_messages = messages

    ##################################################
    # INTERACT :: SHOW
    # Show a single message
    ##################################################
    def show(self):
        id_ = self._prompt_for_id("display")
        asset_control = self._p_messages.get_control(id_)
        if asset_control == False:
            print(f"ERROR! Message ID \'{id_}\' does not exist")
        elif control.security_condition_read(asset_control, self._control):
            self._p_messages.show(id_)
        else:
            print(f"ERROR! Your security clearance is too low to read message #{id_}")
        print()

    ##################################################
    # INTERACT :: DISPLAY
    # Display the set of messages
    ################################################## 
    def display(self):
        print("Messages:")
        self._p_messages.display()
        print()

    ##################################################
    # INTERACT :: ADD
    # Add a single message
    ################################################## 
    def add(self):
        asset_control_str = self._prompt_for_line("security clearance")
        asset_control = control.from_string[asset_control_str]
        if control.security_condition_write(asset_control, self._control):
            self._p_messages.add(self._prompt_for_line("message"),
                                self._username,
                                self._prompt_for_line("date"),
                                asset_control)
        else:
            print(f"ERROR! Your security clearance is too high to create a message with a security clearance of {asset_control_str}")

    ##################################################
    # INTERACT :: UPDATE
    # Update a single message
    ################################################## 
    def update(self):
        id_ = self._prompt_for_id("update")
        asset_control = self._p_messages.get_control(id_)
        if asset_control == False:
            print(f"ERROR! Message ID \'{id_}\' does not exist\n")
        elif control.security_condition_write(asset_control, self._control):
            self._p_messages.show(id_)
            self._p_messages.update(id_, self._prompt_for_line("message"))
        else:
            print(f"ERROR! Your security clearance is too high to update message #{id_}")
        print()
            
    ##################################################
    # INTERACT :: REMOVE
    # Remove one message from the list
    ################################################## 
    def remove(self):
        id_ = self._prompt_for_id("delete")
        asset_control = self._p_messages.get_control(id_)
        if control.security_condition_read(asset_control, self._control):
            self._p_messages.remove(id_)
        else:
            print(f"ERROR! Your security clearance is too low to delete message #{id_}")

    ##################################################
    # INTERACT :: PROMPT FOR LINE
    # Prompt for a line of input
    ################################################## 
    def _prompt_for_line(self, verb):
        return input(f"Please provide a {verb}: ")

    ##################################################
    # INTERACT :: PROMPT FOR ID
    # Prompt for a message ID
    ################################################## 
    def _prompt_for_id(self, verb):
        return int(input(f"Select the message ID to {verb}: "))

    ##################################################
    # INTERACT :: AUTHENTICATE
    # Authenticate the user: find their control level
    ################################################## 
    def _authenticate(self, username, password):
        id_ = self._id_from_user(username)
        return ID_INVALID != id_ and password == users[id_].password

    ##################################################
    # INTERACT :: ID FROM USER
    # Find the ID of a given user
    ################################################## 
    def _id_from_user(self, username):
        for id_user in range(len(users)):
            if username == users[id_user].name:
                return id_user
        return ID_INVALID

#####################################################
# INTERACT :: DISPLAY USERS
# Display the set of users in the system
#####################################################
def display_users():
    for user in users:
        print(f"\t{user.name}\t({control.to_string[user.control]})")

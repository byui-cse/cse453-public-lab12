########################################################################
# COMPONENT:
#    CONTROL
# Author:
#    Br. Helfrich, Kyle Mueller, Martin Melerio, Andersen Stewart, Abel Wenning
# Summary: 
#    This class stores the notion of Bell-LaPadula
########################################################################

from enum import Enum
from functools import total_ordering

@total_ordering
class Control(Enum):
    """ Security clearance """
    Public = 0
    Confidential = 1
    Privileged = 2
    Secret = 3
    # enable equivalency comparison
    def __lt__(self, other):
        if self.__class__ is other.__class__:
          return self.value < other.value
        return NotImplemented

from_string = {
    "Public": Control.Public,
    "Confidential": Control.Confidential,
    "Privileged": Control.Privileged,
    "Secret": Control.Secret,
}

to_string = {
    Control.Public: "Public",
    Control.Confidential: "Confidential",
    Control.Privileged: "Privileged",
    Control.Secret: "Secret",
}

def security_condition_read(asset_control: Control, subject_control: Control) -> bool:
    """Enforce "no read up"

    Prohibit information from being read/deleted by users with lower security clearances.
    """
    return subject_control >= asset_control

def security_condition_write(asset_control: Control, subject_control: Control) -> bool:
    """Enforce "no write down"

    Prohibit information from being created/updated for users with lower security clearances.
    """
    return subject_control <= asset_control

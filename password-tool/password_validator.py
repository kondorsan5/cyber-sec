class PasswordValidator:
    def __init__(self, 
                 min_length=16, 
                 require_lower=True, 
                 require_upper=True, 
                 require_digit=True, 
                 require_special=True,
                 special_charset = set("!@#$%^&*"),
                 problems = []    
                 ):

        if min_length < 1:
            raise ValueError("min_length cannot be less than 1")
        self.min_length = min_length
        self.require_lower = require_lower
        self.require_upper = require_upper
        self.require_digit = require_digit
        self.require_special = require_special
        self.special_charset = special_charset
        self.problems = problems

    def __repr__(self):
        return (
            f"PasswordValidator(min_length={self.min_length}, "
            f"require_upper={self.require_upper}, "
            f"require_lower={self.require_lower}, "
            f"require_digit={self.require_digit}, "
            f"require_special={self.require_special})"
        )

    def printReport(self, argument):
        if argument:
            if len(self.problems) == 0:
                print("Password OK\n")
            for problem in self.problems:
                print(problem)
            print("------------------------")
        else:
            if len(self.problems) == 0:
                print("Password OK\n")
            print("------------------------")   
            print("Password NOT OK")
        self.problems.clear()

    def validate_password(self, password):   
        self.problems.clear()
        if len(password) == 0 or password == '\n':
            self.problems.append("Password cannot be empty")
            return

        if len(password) < self.min_length:
            self.problems.append(f"Password has less than {self.min_length} characters")

        if password.startswith(" ") or password.endswith(" "):
            self.problems.append("Whitespace detected, make sure the password doesn't have whitespaces")

        if self.require_digit:
            if not any(char.isdigit() for char in password):
                self.problems.append("The password should contain a number")

        if self.require_lower:
            if not any(char.islower() for char in password):
                self.problems.append("The password should contain small letters")

        if self.require_upper:
            if not any(char.isupper() for char in password):
                self.problems.append("The password should contain uppercase")

        if self.require_special:
            if not any(char in self.special_charset for char in password):
                self.problems.append("The password should contain a special character")
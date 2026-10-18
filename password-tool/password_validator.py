class PasswordValidator:
    def __init__(self, 
                 min_length=14, 
                 special_charset = set("!@#$%^&*"),
                 require_upper=True, 
                 require_lower=True, 
                 require_digit=True, 
                 require_special=True
                 ):
                 
        
        if min_length < 1:
            raise ValueError("min_length cannot be less than 1")
        self.min_length = min_length
        self.require_upper = require_upper
        self.require_lower = require_lower
        self.require_digit = require_digit
        self.require_special = require_special
        self.special_charset = special_charset

    def __repr__(self):
        return (
            f"PasswordValidator(min_length={self.min_length}, "
            f"require_upper={self.require_upper}, "
            f"require_lower={self.require_lower}, "
            f"require_digit={self.require_digit}, "
            f"require_special={self.require_special})"
        )

    def validate_password(self, password):   
        problems = []

        if len(password) == 0:
            print("Password cannot be empty, aborting")
            return
        
        if len(password) < self.min_length:
            problems.append(f"Password has less than {self.min_length} characters")

        if password.startswith(" ") or password.endswith(" "):
            problems.append("Whitespace detected, make sure the password doesn't have whitespaces")
    
        if not any(char.isdigit() for char in password):
            problems.append("The password should contain a number")

        if not any(char.islower() for char in password):
            problems.append("The password should contain small letters")

        if not any(char.isupper() for char in password):
            problems.append("The password should contain uppercase")

        if not any(char in self.special_charset for char in password):
            problems.append("The password should contain a special character")

        if len(problems) == 0:
            print("Password OK")
            pass
        for problem in problems:
            print(password)
            print(problem)
        print("------------------------")
        

        
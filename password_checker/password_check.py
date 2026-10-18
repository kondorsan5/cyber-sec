problems = []

test_cases = {
    "Empty password" : "",
    "Password too short" : "admin",
    "No uppercase" : "ord123",
    "No number" : "Password",
    "No special character" : "Password123" ,
    "Whitespace in the beginning/end" : " password123! ",
    "Proper password" : "Passwor#d123!",
}

def validate_password(password, min_length):   
    special_chars = set("!@#$%^&*")

    if len(password) == 0:
        problems.append("Password cannot be empty, aborting")
        return problems
    
    if len(password) < min_length:
        problems.append(f"Password has less than {min_length} characters")
   
    if password.startswith(" ") or password.endswith(" "):
        problems.append("Whitespace detected, make sure the password doesn'nt have whitespaces")
   
    if not any(char.isdigit() for char in password):
        problems.append("The password should contain a number")

    if not any(char.islower() for char in password):
        problems.append("The password should contain small letters")

    if not any(char.isupper() for char in password):
        problems.append("The password should contain uppercase")

    if not any(char in special_chars for char in password):
        problems.append("The password should contain a special character")

def read_min_length(): 
    user_value = input("Input required password length: ")
    try:
        min_length = int(user_value)
    except ValueError:
        print("Wrong value, the needs to be a number")
        raise
    return min_length
        

def read_password():
    return input("Input a password: ")

def print_result(problems):
    for note in problems:
        print(f"{note} \n")
    problems.clear()

def main():
    min_length = read_min_length()
    if(test_cases): 
        for case, password in test_cases.items():
            validate_password(password, min_length)

            print(f"{case} : " + f" {password}")
            print_result(problems)
            print("===================================\n")

    password = read_password()
    validate_password(password, min_length)
    print_result(problems)    


if __name__ ==  "__main__":
    main()
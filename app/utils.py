import string
def validate_password(password):
    num_of_char = len(password)
    has_upper = any(c.isupper() for c in password)
    has_lower = any(c.islower() for c in password)
    has_digit = any(c.isdigit() for c in password)
    has_special = any(c in string.punctuation for c in password)
    
    return num_of_char >=12 and has_upper and has_lower and has_digit and has_special
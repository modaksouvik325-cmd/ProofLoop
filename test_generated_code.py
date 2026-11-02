def is_even(n):
    return n % 2 == 0


# Independent test cases
assert is_even(2) == True
assert is_even(7) == False
assert is_even(0) == True
assert is_even(-4) == True

print("All tests passed!")
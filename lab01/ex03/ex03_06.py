def xoa_phan_tu(dictionary, key):
    if key in dictionary:
        del dictionary[key]
        return True
    else:
        return False
    
my_dict = {'a': 1, 'b': 2, 'c': 3, 'd': 4}
key_to_remove = 'b'
result = xoa_phan_tu(my_dict, key_to_remove)
if result:
    print(f"phan tu da duoc xoa tu Dictionary", my_dict)
else:
    print("Khong tim thay phan tu")

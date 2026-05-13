def tao_tuple_tu_list(lst):
    return tuple(lst)

input_str = input("Nhap mot danh sach cac so, cach nhau boi dau ',' : ")
numbers = list(map(int, input_str.split(",")))

my_tuple = tao_tuple_tu_list(numbers)
print("list: ", numbers)
print("tuple: ", my_tuple)

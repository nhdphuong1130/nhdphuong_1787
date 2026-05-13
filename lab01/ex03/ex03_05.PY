def dem_so_lan_xuat_hien(lst):
    count_dict = {}
    for item in lst:
        if item in count_dict:
            count_dict[item] += 1
        else:
            count_dict[item] = 1
    return count_dict

input_str = input("Nhap danh sach cac tu, cach nhau bang dau cach: ")
word_list = input_str.split()

so_lan_xuat_hien = dem_so_lan_xuat_hien(word_list)
print("So lan xuat hien cua cac phan tu: ", so_lan_xuat_hien)
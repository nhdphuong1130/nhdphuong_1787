so_gio_lam = float(input("Nhap so gio lam: "))
luong_gio = float(input("Nhap luong theo gio: "))
gio_tieu_chuan = 44
gio_vuot_chuan = max(0, so_gio_lam - gio_tieu_chuan)

thuc_linh = (gio_tieu_chuan * luong_gio) + (gio_vuot_chuan * luong_gio * 1.5)
print("Thuc linh cua nhan vien la:", thuc_linh)
from QuanLySinhVien import QuanLySinhVien

qlsv = QuanLySinhVien()

while (1 == 1):
    print("\nCHUONG TRINH QUAN LY SINH VIEN")
    print("********************MENU********************")
    print("**  1. Them sinh vien.                        **")
    print("**  2. Cap nhat thong tin sinh vien boi ID.  **")
    print("**  3. Xoa sinh vien boi ID.                 **")
    print("**  4. Tim kiem sinh vien theo ten.          **")
    print("**  5. Sap xep sinh vien theo diem TB.       **")
    print("**  6. Sap xep sinh vien theo ten.           **")
    print("**  7. Hien thi danh sach sinh vien.         **")
    print("**  0. Thoat                                 **")
    print("***********************************************")

    key = int(input("Nhap tuy chon: "))
    if (key == 1):
        print("\n1. Them sinh vien.")
        qlsv.nhapSinhVien()
        print("\nThem sinh vien thanh cong!")

    elif (key == 2):
        if (qlsv.soLuongSinhVien() > 0):
            print("\n2. Cap nhat thong tin sinh vien.")
            ID = int(input("Nhap ID: "))
            qlsv.updateSinhVien(ID)
        else:
            print("\nDanh sach sinh vien trong!")

    # Xoa sinh vien theo ID
    elif (key == 3):
        if (qlsv.soLuongSinhVien() > 0):
            print("\n3. Xoa sinh vien.")
            ID = int(input("Nhap ID: "))

            if (qlsv.deleteById(ID)):
                print("\nSinh vien co ID =", ID, "da bi xoa.")
            else:
                print("\nSinh vien co ID =", ID, "khong ton tai.")
        else:
            print("\nDanh sach sinh vien trong!")

    # Tim kiem sinh vien theo ten
    elif (key == 4):
        if (qlsv.soLuongSinhVien() > 0):
            print("\n4. Tim kiem sinh vien theo ten.")
            name = input("Nhap ten can tim: ")

            searchResult = qlsv.findByName(name)
            qlsv.showSinhVien(searchResult)
        else:
            print("\nDanh sach sinh vien trong!")

    # Sap xep theo diem trung binh
    elif (key == 5):
        if (qlsv.soLuongSinhVien() > 0):
            print("\n5. Sap xep sinh vien theo diem trung binh.")

            qlsv.sortByDiemTB()
            qlsv.showSinhVien(qlsv.getListSinhVien())
        else:
            print("\nDanh sach sinh vien trong!")

    # Sap xep theo ten
    elif (key == 6):
        if (qlsv.soLuongSinhVien() > 0):
            print("\n6. Sap xep sinh vien theo ten.")

            qlsv.sortByName()
            qlsv.showSinhVien(qlsv.getListSinhVien())
        else:
            print("\nDanh sach sinh vien trong!")

    # Hien thi danh sach sinh vien
    elif (key == 7):
        if (qlsv.soLuongSinhVien() > 0):
            print("\n7. Hien thi danh sach sinh vien.")

            qlsv.showSinhVien(qlsv.getListSinhVien())
        else:
            print("\nDanh sach sinh vien trong!")

    # Thoat chuong trinh
    elif (key == 0):
        print("\nBan da chon thoat chuong trinh!")
        break

    # Truong hop nhap sai chuc nang
    else:
        print("\nKhong co chuc nang nay!")
        print("Hay chon chuc nang trong hop menu.")
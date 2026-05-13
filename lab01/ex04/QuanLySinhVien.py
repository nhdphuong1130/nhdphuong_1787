from sinhvien import SinhVien

class QuanLySinhVien:
    def __init__(self):
        self.listSinhVien = []

    def generateID(self):
        maxID = 1
        if len(self.listSinhVien) > 0:
            maxID = self.listSinhVien[0]._id
            for sv in self.listSinhVien:
                if maxID < sv._id:
                    maxID = sv._id
            maxID += 1
        return maxID

    def soLuongSinhVien(self):
        return len(self.listSinhVien)

    def nhapSinhVien(self):
        id = self.generateID()
        name = input("Nhap ten sinh vien: ")
        sex = input("Nhap gioi tinh: ")
        major = input("Nhap chuyen nganh: ")
        diemtb = float(input("Nhap diem trung binh: "))

        sv = SinhVien(id, name, sex, major, diemtb)
        self.xeploaiHocLuc(sv)
        self.listSinhVien.append(sv)

    def updateSinhVien(self, id):
        for sv in self.listSinhVien:
            if sv._id == id:
                sv._name = input("Nhap ten sinh vien: ")
                sv._sex = input("Nhap gioi tinh: ")
                sv._major = input("Nhap chuyen nganh: ")
                sv._diemtb = float(input("Nhap diem trung binh: "))
                self.xeploaiHocLuc(sv)
                return True
        print("Khong tim thay sinh vien")
        return False

    def deleteById(self, id):
        for sv in self.listSinhVien:
            if sv._id == id:
                self.listSinhVien.remove(sv)
                return True
        return False

    def findByName(self, keyword):
        result = []
        for sv in self.listSinhVien:
            if keyword.upper() in sv._name.upper():
                result.append(sv)
        return result

    def sortByDiemTB(self):
        self.listSinhVien.sort(key=lambda sv: sv._diemtb)

    def sortByName(self):
        self.listSinhVien.sort(key=lambda sv: sv._name)

    def xeploaiHocLuc(self, sv):
        if sv._diemtb >= 8:
            sv._xeploai = "Gioi"
        elif sv._diemtb >= 6.5:
            sv._xeploai = "Kha"
        elif sv._diemtb >= 5:
            sv._xeploai = "Trung Binh"
        else:
            sv._xeploai = "Yeu"

    def showSinhVien(self, listSV):
        print("{:<5} {:<20} {:<10} {:<15} {:<10} {:<10}".format(
            "ID", "Ten", "GioiTinh", "Nganh", "DiemTB", "HocLuc"
        ))

        for sv in listSV:
            print("{:<5} {:<20} {:<10} {:<15} {:<10} {:<10}".format(
                sv._id,
                sv._name,
                sv._sex,
                sv._major,
                sv._diemtb,
                sv._xeploai
            ))

    def getListSinhVien(self):
        return self.listSinhVien
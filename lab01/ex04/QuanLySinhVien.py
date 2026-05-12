from sinhvien import SinhVien

class QuanLySinhVien:
    listSinhVien = []
    
def generateID(self):
    maxID = 1
    if (self.soLuongSinhVien() > 0):
        maxID = self.listSinhvien[0]._id
        for sv in self.listSinhVien:
            if (maxID < sv._id):
                maxID = sv._id
        maxID = maxID + 1
    return maxID

def soLuongSinhVien(self):
    return len(self.listSinhVien)

def NhapSinhVien(self):
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
        if (sv._id == id):
            name = input("Nhap ten sinh vien: ")
            sex = input("Nhap gioi tinh: ")
            major = input("Nhap chuyen nganh: ")
            diemtb = float(input("Nhap diem trung binh: "))
            sv._name = name
            sv._sex = sex
            sv._major = major
            sv._diemtb = diemtb
            self.xeploaiHocLuc(sv)
        else:
            print("Khong tim thay sinh vien co id: ", id)
    
    def sortByID(self):
        self.listSinhVien.sort(key=lambda sv: sv._id, reverse=False)
        
    def sortByName(self):
        self.listSinhVien.sort(key=lambda sv: sv._name, reverse=False)
        
    def sortByDiemTB(self):
        self.listSinhVien.sort(key=lambda sv: sv._diemtb, reverse=False)
        
    def findByID(self, id)
        
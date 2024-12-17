from tkinter import*
from os import path
from tkinter import filedialog
from tkinter import messagebox
import tkinter.ttk as ttk
import tkinter
from typing import Sized
import PIL
import PIPO_enc_dec
import AES_enc_dec
import time

global filepath, filepath2
filepath = None
filepath2 = None

win = Tk()

#기본적인 창 사이즈랑 색상선택
win.geometry("1300x700")
win.title("imagefile - encryption")
win.option_add("*font","bold 20")
win.config(background= "lightcyan")
######################
#

    

#
#파일선택부분코드

img_befor = PhotoImage(file=r"nomal.png")
img_box = Label(win,image=img_befor)
img_box.place(x=50,y=200)
def path():
    global img_ch,img_box
    global filepath
    filepath = filedialog.askopenfilename()
    
    if ".txt" in filepath:
        img_ch = PhotoImage(file= r"txt.png")
    elif ".png" in filepath:
        img_ch = PhotoImage(file= rf"{filepath}")
    img_box.config(image= img_ch)
    Label(win,text=f"{filepath}",background="lightcyan").place(x=50,y=150)##파일선택시 경로를 확인하게해주는 라벨
    return filepath


bt1 = Button(win,text = "파일선택",width=10,command = path).place(x=175, y=100)#나중에 탐색기랑 연결해서 경로 불러오는거 추가
Label(win,text = "before",width=10,background="lightcyan").place(x=175,y=600)#문구띄우기


#############################
#라디오 버튼으로 블록암호 선택
Label(win,text = "암호",width=10,background="lightcyan").place(x=575,y=200)
block1 =  StringVar()#선택시 사용되는 변수
block_ciper = Radiobutton(win,text="AES",value="AES",variable= block1,background="lightcyan")
block_ciper.place(x = 600,y = 230)
block_ciper2 = Radiobutton(win,text="PIPO",value="PIPO",variable= block1,background="lightcyan")
block_ciper2.place(x = 600,y = 260)

block_ciper2.select()


#라디오버튼으로 운용모드 선택 변수 저장까지
Label(win,text = "운용 모드",width=10,background="lightcyan").place(x=575,y=300)
block2 =  StringVar()#선택시 사용되는 변수
mode1 = Radiobutton(win,text="ECB",value="ECB",variable= block2,background="lightcyan")
mode1.place(x = 600,y = 330)
mode2 = Radiobutton(win,text="CTR",value="CTR",variable= block2,background="lightcyan")
mode2.place(x = 600,y = 360)
mode3 = Radiobutton(win,text="CBC",value="CBC",variable= block2,background="lightcyan")
mode3.place(x = 600,y = 390)
mode3.select()


#라디오 버튼으로 암복호화 선택 
Label(win,text = "암/복호화",width=10,background="lightcyan").place(x=575,y=430)
block3 = StringVar()#선택시 사용되는 변수
enc = Radiobutton(win,text="암호화",value="enc",variable= block3,background="lightcyan")
enc.place(x = 600,y = 460)
dec = Radiobutton(win,text="복호화",value='dec',variable= block3,background="lightcyan")
dec.place(x = 600,y = 490)
dec.select()



########################################

#저장해서 이미지파일 불러오는 부분


Label(win,text = "After",width=10,background="lightcyan").place(x=975,y=600)#문구띄우기
img_after = PhotoImage(file=r"nomal.png")
img_box2 = Label(win,image=img_after)
img_box2.place(x=840,y=200)

def path2():
    global filepath2,img_ch
    filepath2 = filedialog.askdirectory()
    Label(win,text=f"{filepath2}",background="lightcyan").place(x=900,y=150)##파일선택시 경로를 확인하게해주는 라벨
    return filepath2

bt2 = Button(win,text = "저장경로",width=10,command=path2).place(x=975, y=100)#나중에 탐색기랑 연결해서 경로 불러오는거 추가


p_var = DoubleVar()
progressbar2 = ttk.Progressbar(win, maximum = 100, length = 200, variable = p_var).place(x = 575, y = 100)
        


#######################################################
#암호화 함수 연결하는 부분 
def ENC_DEC():

    global img_box2,img_ch2
    var1 = block1.get()
    
    var2 = block2.get() 

    var3 = block3.get()

    key = 281878575415190224962814573000841505910##고정시키고 테스트
    iv =  271731982294907238954960937428083817233##고정시키고 테스트
    nonce = 13166075984199957611
    

    if filepath == None:
        messagebox.showerror("오류","파일을 선택하세요")
        return 1
    elif filepath2 == None:
        messagebox.showerror("오류","파일 경로를 지정하세요")
        return 1

    if ("AES" or "PIPO") in filepath:##제대로 변수가 설정되었는지 테스트하는 코드
        if var1 in filepath:
            1
        else:
            messagebox.showerror("오류","암호를 다시한번 확인하세요")
            return 1
        if var2 in filepath:
            1
        else:
            messagebox.showerror("오류","모드를 다시한번 확인하세요")
            return 1

    

    if ".png" in filepath:
        filetype = "image"
    elif ".txt" in filepath:
        filetype = "txt"
#################AES#####################3
    if (var1 == "AES"):
        if(var2 == "ECB"):
            if(var3 == "enc"):
                AES_enc_dec.AES128_Enc(filepath,filepath2,"ECB",iv,key,nonce)

            elif(var3 == "dec"):
                if("AES" and "ECB" and "Enc" in filepath):
                    AES_enc_dec.AES128_Dec(filepath,filepath2,"ECB",iv,key,nonce)
                else:
                    messagebox.showerror("오류","암호화된 파일인지 다시한번 확인하세요")
                    return 1        
        elif(var2 == "CTR"):
            if(var3 == "enc"):
                AES_enc_dec.AES128_Enc(filepath,filepath2,"CTR",iv,key,nonce)
            elif(var3 == "dec"):
                if("AES" and "CTR" and "Enc" in filepath):
                    AES_enc_dec.AES128_Dec(filepath,filepath2,"CTR",iv,key,nonce)
                else:
                    messagebox.showerror("오류","암호화된 파일인지 다시한번 확인하세요")
                    return 1                        
        elif(var2 == "CBC"):
            if(var3 == "enc"):
                AES_enc_dec.AES128_Enc(filepath,filepath2,"CBC",iv,key,nonce)
            elif(var3 == "dec"):
                if("AES" and "CBC" and "Enc" in filepath):
                    AES_enc_dec.AES128_Dec(filepath,filepath2,"CBC",iv,key,nonce)
                else:
                    messagebox.showerror("오류","암호화된 파일인지 다시한번 확인하세요")
                    return 1
#######################PIPO############################
    elif (var1 == "PIPO"):
        if(var2 == "ECB"):
            if(var3 == "enc"):
                PIPO_enc_dec.PIPO_ENC(filepath,filepath2,"ECB",iv,key)
            elif(var3 == "dec"):
                if("PIPO" and "ECB" and "Enc" in filepath):
                    PIPO_enc_dec.PIPO_DEC(filepath,filepath2,"ECB",iv,key)
                else:
                    messagebox.showerror("오류","암호화된 파일인지 다시한번 확인하세요")
                    return 1
        elif(var2 == "CBC"):
            if(var3 == "enc"):
                PIPO_enc_dec.PIPO_ENC(filepath,filepath2,"CBC",iv,key)
            elif(var3 == "dec"):
                if("PIPO" and "ECB" and "Enc" in filepath):
                    PIPO_enc_dec.PIPO_DEC(filepath,filepath2,"CBC",iv,key)
                else:
                    messagebox.showerror("오류","암호화된 파일인지 다시한번 확인하세요")
                    return 1
        elif(var2 == "CTR"):
            if(var3 == "enc"):
                PIPO_enc_dec.PIPO_ENC(filepath,filepath2,"CTR",iv,key)
            elif(var3 == "dec"):
                if("PIPO" and "ECB" and "Enc" in filepath):
                    PIPO_enc_dec.PIPO_DEC(filepath,filepath2,"CTR",iv,key)
                else:
                    messagebox.showerror("오류","암호화된 파일인지 다시한번 확인하세요")
                    return 1

    if filetype == "image":            
        img_ch2 = PhotoImage(file= rf"{filepath2}"+"\\img_"+ var1 + "_"+var2+"_"+var3+".png")
        img_box2.config(image = img_ch2)
    elif filetype == "txt":
        img_ch2 = PhotoImage(file= rf"{filepath2}"+"\\txt.png")
        img_box2.config(image = img_ch2)
        
    if (var3 == "enc"):
        messagebox.showinfo("알림",f"{var1} {var2}모드로 암호화를 완료했습니다")
    if (var3 == "dec"):
        messagebox.showinfo("알림",f"{var1} {var2}모드로 복호화를 완료했습니다")
    


        

#######################################################
#실행시키는 버튼
Button(win, text = "실행",command= ENC_DEC).place(x= 615,y=550)


win.mainloop()
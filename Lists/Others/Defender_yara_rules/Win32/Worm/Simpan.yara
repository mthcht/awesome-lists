rule Worm_Win32_Simpan_A_2147574872_0
{
    meta:
        author = "defender2yara"
        detection_name = "Worm:Win32/Simpan.A"
        threat_id = "2147574872"
        type = "Worm"
        platform = "Win32: Windows 32-bit platform"
        family = "Simpan"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "40"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "\\System.sys" wide //weight: 1
        $x_1_2 = "at /delete /y" wide //weight: 1
        $x_1_3 = "FSum=replace(FSum,@-@.HTM@-@,@-@@-@)" wide //weight: 1
        $x_1_4 = "FSum=replace(FSum,@-@.HTML@-@,@-@@-@)" wide //weight: 1
        $x_1_5 = "FSum=replace(FSum,@-@/@-@,@-@@-@)" wide //weight: 1
        $x_1_6 = "FSum=replace(location.pathname,@-@%20@-@,@-@ @-@)" wide //weight: 1
        $x_1_7 = "Set WSHShell = CreateObject(@-@WScript.Shell@-@)" wide //weight: 1
        $x_1_8 = "VagNPath0.txt;;;VagNPath1.txt;;;VagNPath2.txt;;;VagNPath3.txt" wide //weight: 1
        $x_5_9 = "WSHShell.Run Chr(34) & FSum & @-@_files\\Image1.scr@-@ & Chr(34)" wide //weight: 5
        $x_5_10 = "\\INDONESIA-RAYA-INDONESIA-MERDEKA-17-AGUSTUS-1945.INF" wide //weight: 5
        $x_1_11 = "\\VagEmO-" wide //weight: 1
        $x_1_12 = "\\VagEmOE-" wide //weight: 1
        $x_1_13 = "\\VagOkSend-" wide //weight: 1
        $x_1_14 = "\\VagSKCon.vbs" wide //weight: 1
        $x_5_15 = "dw#4<=33#2hyhu|=P/W/Z/Wk/I/V/Vx#F=_Zlqgrzv_SLI_FYW651sli" wide //weight: 5
        $x_5_16 = "F=_Ydjdq}dbr{4gd1w{w" wide //weight: 5
        $x_5_17 = "F=_Ydjdq}dbr{4gdbOhzdwlbFrs|Pdvvdo1w{w" wide //weight: 5
        $x_5_18 = "F=_Zlqgrzv" wide //weight: 5
        $x_5_19 = "F=_ZLQGRZV_MDYD" wide //weight: 5
        $x_5_20 = "F=_ZLQGRZV_SLI" wide //weight: 5
        $x_5_21 = "GlvdeohFPG" wide //weight: 5
        $x_5_22 = "GlvdeohUhjlvwu|Wrrov" wide //weight: 5
        $x_5_23 = "GlvdeohWdvnPju" wide //weight: 5
        $x_5_24 = "MsgBox @-@You Must Click @-@ & Chr(34) & @-@YES@-@ & Chr(34) & @-@ to Enable The ActiveX in This Secure Document@-@" wide //weight: 5
        $x_5_25 = "PLFURVRIW>DGREH>DFUREDW" wide //weight: 5
        $x_5_26 = "QrIroghuRswlrqv" wide //weight: 5
        $x_5_27 = "QRUWRQ>DYJ>FLOOLQ>SDQGD>QDY>PFDI>VFDQ>YLUXV>SHUVN\\>YDNVLQ>UHJLVWU\\>WDVN>MDYD>FRQILJXUDWLRQ>FRPPDQG>FPG>FRQWURO>VHD" wide //weight: 5
        $x_1_28 = "VagAgent-" wide //weight: 1
        $x_1_29 = "VagEmO-" wide //weight: 1
        $x_1_30 = "VagEmOE-" wide //weight: 1
        $x_1_31 = "VagFoldNetDomList.drv" wide //weight: 1
        $x_1_32 = "VagInfek.exe" wide //weight: 1
        $x_1_33 = "VagLoadDoc-" wide //weight: 1
        $x_1_34 = "VagMail-" wide //weight: 1
        $x_1_35 = "VagNetDomList.bat" wide //weight: 1
        $x_1_36 = "VagNPath" wide //weight: 1
        $x_1_37 = "VagNPath0.txt" wide //weight: 1
        $x_1_38 = "VagRem.Indo" wide //weight: 1
        $x_1_39 = "VgNPathHtml.txt" wide //weight: 1
        $x_5_40 = "vriwzduh_plfurvriw_Lqwhuqhw#H{soruhu_Pdlq" wide //weight: 5
        $x_5_41 = "vriwzduh_plfurvriw_zlqgrzv_fxuuhqwyhuvlrq_Srolflhv_H{soruhu" wide //weight: 5
        $x_5_42 = "vriwzduh_plfurvriw_zlqgrzv_fxuuhqwyhuvlrq_Srolflhv_V|vwhp" wide //weight: 5
        $x_5_43 = "vriwzduh_plfurvriw_zlqgrzv_fxuuhqwyhuvlrq_uxq" wide //weight: 5
    condition:
        (filesize < 20MB) and
        (
            ((4 of ($x_5_*) and 20 of ($x_1_*))) or
            ((5 of ($x_5_*) and 15 of ($x_1_*))) or
            ((6 of ($x_5_*) and 10 of ($x_1_*))) or
            ((7 of ($x_5_*) and 5 of ($x_1_*))) or
            ((8 of ($x_5_*))) or
            (all of ($x*))
        )
}


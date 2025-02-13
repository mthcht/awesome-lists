rule PWS_Win32_Progent_B_2147575706_0
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:Win32/Progent.B!dll"
        threat_id = "2147575706"
        type = "PWS"
        platform = "Win32: Windows 32-bit platform"
        family = "Progent"
        severity = "Critical"
        info = "dll: Dynamic Link Library component of a malware"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "100"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "\\qservice.exe" ascii //weight: 1
        $x_1_2 = "\\agnt_fps.exe" ascii //weight: 1
        $x_1_3 = "\\agnt_fps.dat" ascii //weight: 1
        $x_1_4 = "\\HookMpi.dll" ascii //weight: 1
        $x_1_5 = "\\agnt_mps.exe" ascii //weight: 1
        $x_1_6 = "\\agnt_mps.dat" ascii //weight: 1
        $x_1_7 = "\\agnt_pnc.exe" ascii //weight: 1
        $x_1_8 = "\\_pnc.dat" ascii //weight: 1
        $x_1_9 = "\\agnt_msn.exe" ascii //weight: 1
        $x_1_10 = "\\agnt_msn.dat" ascii //weight: 1
        $x_1_11 = "\\services.dll" ascii //weight: 1
        $x_1_12 = "\\drivers\\HideMe.sys" ascii //weight: 1
        $x_1_13 = "\\msdirectx.sys" ascii //weight: 1
        $x_1_14 = "\\kurlmon.dll" ascii //weight: 1
        $x_1_15 = "\\msehk.dll" ascii //weight: 1
        $x_1_16 = "\\bszip.dll" ascii //weight: 1
        $x_1_17 = "\\wins32.zip" ascii //weight: 1
        $x_1_18 = "\\FileZilla.xml" ascii //weight: 1
        $x_1_19 = "mcvsescn.exe" ascii //weight: 1
        $x_1_20 = "\\wins32\\" ascii //weight: 1
        $x_1_21 = "\\k_urlmon.dll" ascii //weight: 1
        $x_1_22 = "qservices" ascii //weight: 1
        $x_1_23 = "hookdll" ascii //weight: 1
        $x_1_24 = "H_o_o_k" ascii //weight: 1
        $x_1_25 = "Unh_o_o_k" ascii //weight: 1
        $x_1_26 = "mailpv" ascii //weight: 1
        $x_1_27 = "Pinch" ascii //weight: 1
        $x_5_28 = "Can't dedect" ascii //weight: 5
        $x_5_29 = "Hi criminal =)" ascii //weight: 5
        $x_5_30 = "No more Mail Scanning =)" ascii //weight: 5
        $x_5_31 = "No more Firewall Protection =)" ascii //weight: 5
        $x_5_32 = "mousehook" ascii //weight: 5
        $x_5_33 = "HookBaslat" ascii //weight: 5
        $x_3_34 = "Computer Name    : " ascii //weight: 3
        $x_3_35 = "User Name        : " ascii //weight: 3
        $x_3_36 = "ProductId        : " ascii //weight: 3
        $x_3_37 = "I.Explorer Ver   : " ascii //weight: 3
        $x_3_38 = "Vendor Identifier: " ascii //weight: 3
        $x_3_39 = "Hard Drive(s) List:" ascii //weight: 3
        $x_3_40 = "ProAgent : [" ascii //weight: 3
        $x_3_41 = "Display Adapter(s) Information:" ascii //weight: 3
        $x_3_42 = "Sound Card(s) Information:" ascii //weight: 3
        $x_3_43 = "Ftp Server: " ascii //weight: 3
        $x_3_44 = "PEER FTP PASSWORDS" ascii //weight: 3
        $x_3_45 = "EXEEM PASSWORDS" ascii //weight: 3
        $x_3_46 = "SENDLINK PASSWORDS" ascii //weight: 3
        $x_3_47 = "CHAT ANYWHERE PASSWORDS" ascii //weight: 3
        $x_3_48 = "FTPNOW PASSWORDS" ascii //weight: 3
        $x_3_49 = "DELUXE FTP PASSWORDS" ascii //weight: 3
        $x_3_50 = "DELUXE FTP PRO PASSWORDS" ascii //weight: 3
        $x_3_51 = "MORPHEUS CHAT PASSWORDS" ascii //weight: 3
        $x_3_52 = "BITCOMET PASSWORDS" ascii //weight: 3
        $x_3_53 = "FIREFLY PASSWORDS" ascii //weight: 3
        $x_3_54 = "KEYLOGGER RECORDS" ascii //weight: 3
        $x_3_55 = "URL HISTORY" ascii //weight: 3
        $x_3_56 = "PROCESSES INFORMATION" ascii //weight: 3
        $x_3_57 = "PC INFORMATIONS" ascii //weight: 3
        $x_3_58 = "CUTE FTP PASSWORDS" ascii //weight: 3
        $x_3_59 = "FLASH FXP PASSWORDS" ascii //weight: 3
        $x_3_60 = "WS_FTP PASSWORDS" ascii //weight: 3
        $x_3_61 = "FILEZILLA PASSWORDS" ascii //weight: 3
        $x_3_62 = "CD-KEYS" ascii //weight: 3
        $x_3_63 = "ADDRESS BOOK RECORDS" ascii //weight: 3
        $x_3_64 = "INSTANT MESSENGER PASSWORDS" ascii //weight: 3
        $x_3_65 = "MAIL PASSWORDS" ascii //weight: 3
        $x_3_66 = "CRYPTED DATA" ascii //weight: 3
        $x_3_67 = "PROTECTED STORAGE" ascii //weight: 3
        $x_3_68 = "Not Recorded!" ascii //weight: 3
    condition:
        (filesize < 20MB) and
        (
            ((25 of ($x_3_*) and 25 of ($x_1_*))) or
            ((26 of ($x_3_*) and 22 of ($x_1_*))) or
            ((27 of ($x_3_*) and 19 of ($x_1_*))) or
            ((28 of ($x_3_*) and 16 of ($x_1_*))) or
            ((29 of ($x_3_*) and 13 of ($x_1_*))) or
            ((30 of ($x_3_*) and 10 of ($x_1_*))) or
            ((31 of ($x_3_*) and 7 of ($x_1_*))) or
            ((32 of ($x_3_*) and 4 of ($x_1_*))) or
            ((33 of ($x_3_*) and 1 of ($x_1_*))) or
            ((34 of ($x_3_*))) or
            ((1 of ($x_5_*) and 23 of ($x_3_*) and 26 of ($x_1_*))) or
            ((1 of ($x_5_*) and 24 of ($x_3_*) and 23 of ($x_1_*))) or
            ((1 of ($x_5_*) and 25 of ($x_3_*) and 20 of ($x_1_*))) or
            ((1 of ($x_5_*) and 26 of ($x_3_*) and 17 of ($x_1_*))) or
            ((1 of ($x_5_*) and 27 of ($x_3_*) and 14 of ($x_1_*))) or
            ((1 of ($x_5_*) and 28 of ($x_3_*) and 11 of ($x_1_*))) or
            ((1 of ($x_5_*) and 29 of ($x_3_*) and 8 of ($x_1_*))) or
            ((1 of ($x_5_*) and 30 of ($x_3_*) and 5 of ($x_1_*))) or
            ((1 of ($x_5_*) and 31 of ($x_3_*) and 2 of ($x_1_*))) or
            ((1 of ($x_5_*) and 32 of ($x_3_*))) or
            ((2 of ($x_5_*) and 21 of ($x_3_*) and 27 of ($x_1_*))) or
            ((2 of ($x_5_*) and 22 of ($x_3_*) and 24 of ($x_1_*))) or
            ((2 of ($x_5_*) and 23 of ($x_3_*) and 21 of ($x_1_*))) or
            ((2 of ($x_5_*) and 24 of ($x_3_*) and 18 of ($x_1_*))) or
            ((2 of ($x_5_*) and 25 of ($x_3_*) and 15 of ($x_1_*))) or
            ((2 of ($x_5_*) and 26 of ($x_3_*) and 12 of ($x_1_*))) or
            ((2 of ($x_5_*) and 27 of ($x_3_*) and 9 of ($x_1_*))) or
            ((2 of ($x_5_*) and 28 of ($x_3_*) and 6 of ($x_1_*))) or
            ((2 of ($x_5_*) and 29 of ($x_3_*) and 3 of ($x_1_*))) or
            ((2 of ($x_5_*) and 30 of ($x_3_*))) or
            ((3 of ($x_5_*) and 20 of ($x_3_*) and 25 of ($x_1_*))) or
            ((3 of ($x_5_*) and 21 of ($x_3_*) and 22 of ($x_1_*))) or
            ((3 of ($x_5_*) and 22 of ($x_3_*) and 19 of ($x_1_*))) or
            ((3 of ($x_5_*) and 23 of ($x_3_*) and 16 of ($x_1_*))) or
            ((3 of ($x_5_*) and 24 of ($x_3_*) and 13 of ($x_1_*))) or
            ((3 of ($x_5_*) and 25 of ($x_3_*) and 10 of ($x_1_*))) or
            ((3 of ($x_5_*) and 26 of ($x_3_*) and 7 of ($x_1_*))) or
            ((3 of ($x_5_*) and 27 of ($x_3_*) and 4 of ($x_1_*))) or
            ((3 of ($x_5_*) and 28 of ($x_3_*) and 1 of ($x_1_*))) or
            ((3 of ($x_5_*) and 29 of ($x_3_*))) or
            ((4 of ($x_5_*) and 18 of ($x_3_*) and 26 of ($x_1_*))) or
            ((4 of ($x_5_*) and 19 of ($x_3_*) and 23 of ($x_1_*))) or
            ((4 of ($x_5_*) and 20 of ($x_3_*) and 20 of ($x_1_*))) or
            ((4 of ($x_5_*) and 21 of ($x_3_*) and 17 of ($x_1_*))) or
            ((4 of ($x_5_*) and 22 of ($x_3_*) and 14 of ($x_1_*))) or
            ((4 of ($x_5_*) and 23 of ($x_3_*) and 11 of ($x_1_*))) or
            ((4 of ($x_5_*) and 24 of ($x_3_*) and 8 of ($x_1_*))) or
            ((4 of ($x_5_*) and 25 of ($x_3_*) and 5 of ($x_1_*))) or
            ((4 of ($x_5_*) and 26 of ($x_3_*) and 2 of ($x_1_*))) or
            ((4 of ($x_5_*) and 27 of ($x_3_*))) or
            ((5 of ($x_5_*) and 16 of ($x_3_*) and 27 of ($x_1_*))) or
            ((5 of ($x_5_*) and 17 of ($x_3_*) and 24 of ($x_1_*))) or
            ((5 of ($x_5_*) and 18 of ($x_3_*) and 21 of ($x_1_*))) or
            ((5 of ($x_5_*) and 19 of ($x_3_*) and 18 of ($x_1_*))) or
            ((5 of ($x_5_*) and 20 of ($x_3_*) and 15 of ($x_1_*))) or
            ((5 of ($x_5_*) and 21 of ($x_3_*) and 12 of ($x_1_*))) or
            ((5 of ($x_5_*) and 22 of ($x_3_*) and 9 of ($x_1_*))) or
            ((5 of ($x_5_*) and 23 of ($x_3_*) and 6 of ($x_1_*))) or
            ((5 of ($x_5_*) and 24 of ($x_3_*) and 3 of ($x_1_*))) or
            ((5 of ($x_5_*) and 25 of ($x_3_*))) or
            ((6 of ($x_5_*) and 15 of ($x_3_*) and 25 of ($x_1_*))) or
            ((6 of ($x_5_*) and 16 of ($x_3_*) and 22 of ($x_1_*))) or
            ((6 of ($x_5_*) and 17 of ($x_3_*) and 19 of ($x_1_*))) or
            ((6 of ($x_5_*) and 18 of ($x_3_*) and 16 of ($x_1_*))) or
            ((6 of ($x_5_*) and 19 of ($x_3_*) and 13 of ($x_1_*))) or
            ((6 of ($x_5_*) and 20 of ($x_3_*) and 10 of ($x_1_*))) or
            ((6 of ($x_5_*) and 21 of ($x_3_*) and 7 of ($x_1_*))) or
            ((6 of ($x_5_*) and 22 of ($x_3_*) and 4 of ($x_1_*))) or
            ((6 of ($x_5_*) and 23 of ($x_3_*) and 1 of ($x_1_*))) or
            ((6 of ($x_5_*) and 24 of ($x_3_*))) or
            (all of ($x*))
        )
}


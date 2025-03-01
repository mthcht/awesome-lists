rule TrojanDownloader_O97M_Zloader_DR_2147763243_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Zloader.DR!MTB"
        threat_id = "2147763243"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Zloader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Environ$(\"USERPROFILE\") + \"\\j5Iss52\"" ascii //weight: 1
        $x_1_2 = "Environ$(\"USERPROFILE\") + \"\\n5Is5s52\"" ascii //weight: 1
        $x_2_3 = "Right(UserForm2.Tag, 11) + Temporary + \".xls \"" ascii //weight: 2
        $x_2_4 = "create Right(UserForm1.Caption, 9) + Temporary + \".dll,R1\", Null, Null, Data2" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_2_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule TrojanDownloader_O97M_Zloader_SS_2147767757_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Zloader.SS!MTB"
        threat_id = "2147767757"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Zloader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "zcomtech.com/rob122DzjsdFA.dll -J -o c" ascii //weight: 1
        $x_1_2 = "c:\\users\\public\\cdnup" ascii //weight: 1
        $x_1_3 = "RIZJZCBR" ascii //weight: 1
        $x_1_4 = "rundll32 c:\\u" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Zloader_SS_2147767757_1
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Zloader.SS!MTB"
        threat_id = "2147767757"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Zloader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "curl http://185.244.41.29/ooi" ascii //weight: 1
        $x_1_2 = "wy.pdf -J -o c:\\users\\public\\cdnupdate" ascii //weight: 1
        $x_1_3 = "rundll32 c:\\users\\public\\cdnupdaterapi.png" ascii //weight: 1
        $x_1_4 = "CUVPQRBAXWGP" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Zloader_VA_2147769928_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Zloader.VA!MTB"
        threat_id = "2147769928"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Zloader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "8"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {20 3d 20 4e 6f 74 68 69 6e 67 02 00 44 6f 45 76 65 6e 74 73 02 00 43 61 6c 6c 42 79 4e 61 6d 65 20 [0-6] 2c 20 [0-6] 2c 20 [0-8] 20 3d 20 4e 6f 74 68 69 6e 67 02 00 44 6f 45 76 65 6e 74 73}  //weight: 1, accuracy: Low
        $x_1_2 = "UserForm1.ComboBox4 = UserForm1.ComboBox4 & \"0\"" ascii //weight: 1
        $x_1_3 = "Application.OnTime Now + TimeSerial(0, 0, 20), \"ThisDocument.nnn\"" ascii //weight: 1
        $x_1_4 = ".sheets(1)" ascii //weight: 1
        $x_1_5 = {50 72 69 76 61 74 65 20 53 75 62 20 55 73 65 72 46 6f 72 6d 5f 49 6e 69 74 69 61 6c 69 7a 65 28 29 [0-5] 43 61 6c 6c 42 79 4e 61 6d 65 20 41 63 74 69 76 65 44 6f 63 75 6d 65 6e 74 2e [0-5] 2c 20 41 63 74 69 76 65 44 6f 63 75 6d 65 6e 74 2e [0-5] 2c 20 56 62 4d 65 74 68 6f 64 2c 20 41 63 74 69 76 65 44 6f 63 75 6d 65 6e 74 2e}  //weight: 1, accuracy: Low
        $x_1_6 = "Sub nnn()" ascii //weight: 1
        $x_1_7 = "Workbooks.Open(FileName:=UserForm2.ComboBox1, Password:=UserForm1.ComboBox2)" ascii //weight: 1
        $x_1_8 = ".Run \"ThisDocument.nnn\"" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Zloader_RE_2147776628_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Zloader.RE!MTB"
        threat_id = "2147776628"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Zloader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Replace(Russian, val, letter)" ascii //weight: 1
        $x_1_2 = "String(2, \"/\")" ascii //weight: 1
        $x_1_3 = "1230948%1230948@j." ascii //weight: 1
        $x_1_4 = "\"mp/\" + \"4knsknfk29whh\"" ascii //weight: 1
        $x_1_5 = "String(1, \"h\") + String(2, \"t\")" ascii //weight: 1
        $x_1_6 = "Shell (fire)" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Zloader_RVB_2147777160_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Zloader.RVB!MTB"
        threat_id = "2147777160"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Zloader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "ttp://aqv.to/12.msi" ascii //weight: 1
        $x_1_2 = "ProgramW6432:~15%iexec.exe" ascii //weight: 1
        $x_1_3 = "powershel" ascii //weight: 1
        $x_1_4 = "cmd.exe" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

rule TrojanDownloader_O97M_Zloader_ZA_2147779020_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Zloader.ZA!MTB"
        threat_id = "2147779020"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Zloader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Environ$(\"AppData\") & \"\\\" &" ascii //weight: 1
        $x_1_2 = "Decrypt(\"fyf/ttsd\")" ascii //weight: 1
        $x_1_3 = "AppData & Chr(Asc(b) - 1)" ascii //weight: 1
        $x_1_4 = "= StrReverse(enc)" ascii //weight: 1
        $x_1_5 = "LOP & Chr(Asc(Mid(JOOOK, VON, 1)) - 13)" ascii //weight: 1
        $x_1_6 = "URLDownloadToFileA" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


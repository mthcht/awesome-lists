rule TrojanDownloader_O97M_ZLoader_MK_2147754475_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/ZLoader.MK!MSR"
        threat_id = "2147754475"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "ZLoader"
        severity = "Critical"
        info = "MSR: Microsoft Security Response"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {63 3a 5c 70 69 70 65 64 69 72 5c [0-21] 2e 76 62 73 20 68 74 74 70 3a 2f 2f 32 30 35 2e 31 38 35 2e 31 32 32 2e 32 34 36 2f 66 69 6c 65 73 2f [0-5] 2e 65 78 65 20 63 3a 5c 70 69 70 65 64 69 72 5c [0-21] 2e 65 78 65}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_ZLoader_DHA_2147754476_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/ZLoader.DHA!MTB"
        threat_id = "2147754476"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "ZLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "= CreateFile(\"c:\\pipedir\\obsrecord.cmd\" _" ascii //weight: 1
        $x_1_2 = "= CreateObject(\"\"Scripting.FileSystemObject\"\") >> %NKFDGIDIFNSNF%\"" ascii //weight: 1
        $x_1_3 = "c:\\pipedir\\NKFDGIDIFNSNF.vbs http://205.185.122.246/files/1.exe c:\\pipedir\\LODFOJKFG.exe" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_ZLoader_HZA_2147754886_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/ZLoader.HZA!MTB"
        threat_id = "2147754886"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "ZLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "hExportFile = CreateFile(\"c:\\pipedir\\obsrecord.cmd\"" ascii //weight: 1
        $x_1_2 = "\"echo Set NeHD = CreateObject(\"\"MSXML2.Se\" + \"rverXMLHTTP\"\")" ascii //weight: 1
        $x_1_3 = "\"echo Set a = CreateObject(\"\"Scripting.FileSystemObject\"\")" ascii //weight: 1
        $x_1_4 = {22 70 74 20 63 3a 5c 70 69 70 65 64 69 72 5c 4e 4b 46 44 47 49 44 49 46 4e 53 4e 46 2e 76 62 73 20 68 74 74 70 3a 2f 2f [0-160] 2e 70 68 70 20 63 3a 5c 70 69 70 65 64 69 72 5c 4c 4f 44 46 4f 4a 4b 46 47 2e 65 78 65 22}  //weight: 1, accuracy: Low
        $x_1_5 = {22 70 74 20 63 3a 5c 70 69 70 65 64 69 72 5c 4e 4b 46 44 47 49 44 49 46 4e 53 4e 46 2e 76 62 73 20 68 74 74 70 3a 2f 2f [0-160] 2e 65 78 65 20 63 3a 5c 70 69 70 65 64 69 72 5c 4c 4f 44 46 4f 4a 4b 46 47 2e 65 78 65 22}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (4 of ($x*))
}

rule TrojanDownloader_O97M_ZLoader_ZLD_2147766455_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/ZLoader.ZLD!MTB"
        threat_id = "2147766455"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "ZLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "https://download24.top/dllDds22xdsdf78/xlsp.c10" ascii //weight: 1
        $x_1_2 = "C:\\uOWMrmn\\lqbUcGh\\BKiPsIo.dll" ascii //weight: 1
        $x_1_3 = "URLDownloadToFileA" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_ZLoader_PLL_2147767005_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/ZLoader.PLL!MTB"
        threat_id = "2147767005"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "ZLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "https://puredoc2020.top/dllDds22xddf232/xls.c10" ascii //weight: 1
        $x_1_2 = "C:\\auOIxdm\\mkpbUbG\\yBKTOrI.dll" ascii //weight: 1
        $x_1_3 = "URLDownloadToFileA" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_ZLoader_BK_2147767732_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/ZLoader.BK!MTB"
        threat_id = "2147767732"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "ZLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "http://cocinashogarmobiliario.com/photo.png" ascii //weight: 1
        $x_1_2 = "c:\\users\\public\\photo.png" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_ZLoader_PSW_2147769213_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/ZLoader.PSW!MTB"
        threat_id = "2147769213"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "ZLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "https://purefile24.top/4352wedfoifom.php" ascii //weight: 1
        $x_1_2 = "C:\\uqqpufY\\fKkWmps\\vMsySaP.dll" ascii //weight: 1
        $x_1_3 = "URLDownloadToFileA" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_ZLoader_PWT_2147770367_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/ZLoader.PWT!MTB"
        threat_id = "2147770367"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "ZLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "https://downlfile24.top/kdjasd.php" ascii //weight: 1
        $x_1_2 = "C:\\TlLlwqJ\\sPyJPLX\\YyIUwQv.dll" ascii //weight: 1
        $x_1_3 = "URLDownloadToFileA" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_ZLoader_PA_2147770377_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/ZLoader.PA!MTB"
        threat_id = "2147770377"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "ZLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {63 00 4d 00 44 00 2e 00 65 00 58 00 65 00 20 00 20 00 2f 00 63 00 20 00 50 00 4f 00 77 00 45 00 72 00 73 00 68 00 65 00 4c 00 4c 00 2e 00 45 00 78 00 65 00 20 00 20 00 2d 00 65 00 58 00 20 00 42 00 59 00 70 00 41 00 53 00 53 00 20 00 2d 00 4e 00 4f 00 70 00 20 00 2d 00 77 00 20 00 31 00 20 00 69 00 45 00 58 00 28 00 20 00 43 00 55 00 52 00 6c 00 [0-4] 28 00 27 00 68 00 74 74 00 70 00 3a 00 2f 00 2f 00 34 00 35 00 2e 00 31 00 35 00 33 00 2e 00 32 00 30 00 33 00 2e 00 35 00 34 00 2f 00 44 00 6f 00 63 00 32 00 32 00 41 00 2e 00 6a 00 [0-8] 70 00 [0-8] 67 00}  //weight: 1, accuracy: Low
        $x_1_2 = {63 4d 44 2e 65 58 65 20 20 2f 63 20 50 4f 77 45 72 73 68 65 4c 4c 2e 45 78 65 20 20 2d 65 58 20 42 59 70 41 53 53 20 2d 4e 4f 70 20 2d 77 20 31 20 69 45 58 28 20 43 55 52 6c [0-4] 28 27 68 74 74 70 3a 2f 2f 34 35 2e 31 35 33 2e 32 30 33 2e 35 34 2f 44 6f 63 32 32 41 2e 6a [0-8] 70 [0-8] 67}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule TrojanDownloader_O97M_ZLoader_VIS_2147773038_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/ZLoader.VIS!MTB"
        threat_id = "2147773038"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "ZLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "UserForm1.ComboBox4 = UserForm1.ComboBox4 & \"0\"" ascii //weight: 1
        $x_1_2 = "Application.OnTime Now + TimeSerial(0, 0, 20), \"ThisDocument" ascii //weight: 1
        $x_1_3 = "Workbooks.Open(FileName:=UserForm2.ComboBox1, Password:=UserForm1.ComboBox2)" ascii //weight: 1
        $x_1_4 = ".Run \"ThisDocument.\" & " ascii //weight: 1
        $x_1_5 = "= Application.Options.MatchFuzzy" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_ZLoader_PIN_2147777351_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/ZLoader.PIN!MTB"
        threat_id = "2147777351"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "ZLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = ".ComboBox4 = UserForm1.ComboBox4 & \"0\"" ascii //weight: 1
        $x_1_2 = "Application.OnTime Now + TimeSerial(0, 0, 20), \"ThisDocument" ascii //weight: 1
        $x_1_3 = "Workbooks.Open(FileName:=UserForm2.ComboBox1, Password:=UserForm1.ComboBox2)" ascii //weight: 1
        $x_1_4 = ".Run \"ThisDocument.\" & " ascii //weight: 1
        $x_1_5 = ".Documents.Open ActiveDocument.FullName, ReadOnly:=True" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


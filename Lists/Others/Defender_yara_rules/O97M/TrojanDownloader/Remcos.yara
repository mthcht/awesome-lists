rule TrojanDownloader_O97M_Remcos_GM_2147760041_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Remcos.GM!MTB"
        threat_id = "2147760041"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Remcos"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {53 65 74 20 [0-32] 20 3d 20 43 72 65 61 74 65 4f 62 6a 65 63 74 28 22 4d 73 78 6d 6c 32 2e 44 4f 4d 44 6f 63 75 6d 65 6e 74 2e 33 2e 30 22 29}  //weight: 1, accuracy: Low
        $x_1_2 = "Load \"http://185.172.110.217/robx/remit.jpg" ascii //weight: 1
        $x_1_3 = "Attribute VB_Name = \"ovwS" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Remcos_YA_2147761910_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Remcos.YA!MTB"
        threat_id = "2147761910"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Remcos"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Pspl.Create(Nxayp, Null, Null, mh0f5)" ascii //weight: 1
        $x_1_2 = "Set Pspl = GetObject(A1)" ascii //weight: 1
        $x_1_3 = "Nxayp = A2 + \" -WindowStyle Hidden $fd4er7f0=" ascii //weight: 1
        $x_1_4 = "$jm -join ''|I`E`X" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Remcos_SS_2147769208_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Remcos.SS!MTB"
        threat_id = "2147769208"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Remcos"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {53 65 74 20 90 02 0f 20 3d 20 4d 56 4e 49 44 2e 4f 70 65 6e 54 65 78 74 46 69 6c 65 28 4f 47 6c 71 20 2b 20 22 5c 5a 72 54 53 79 2e 76 62 73 22 2c 20 38 2c 20 54 72 75 65 29}  //weight: 1, accuracy: High
        $x_1_2 = "Dir(f5fg0e + \"\\ZrTSy.vbs\") = \"\" Then" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Remcos_RVA_2147828498_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Remcos.RVA!MTB"
        threat_id = "2147828498"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Remcos"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "\"powe\" + \"rs\" + Range(\"F100\").Value" ascii //weight: 1
        $x_1_2 = "CreateObject(VMWYB())" ascii //weight: 1
        $x_1_3 = "ggg.ExecMethod_(HByn(), f8df00)" ascii //weight: 1
        $x_1_4 = "\"C\" + ActiveSheet.PageSetup.LeftFooter + fjjdf()" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Remcos_RVA_2147828498_1
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Remcos.RVA!MTB"
        threat_id = "2147828498"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Remcos"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "CreateObject(ActiveSheet.PageSetup.CenterHeader)" ascii //weight: 1
        $x_1_2 = {5a 49 41 52 62 28 29 2e 45 78 65 63 20 6b 6f 67 48 33 0d 0a 45 6e 64 20 46 75 6e 63 74 69 6f 6e}  //weight: 1, accuracy: High
        $x_1_3 = "For Each ZvFDlwx In ActiveWorkbook.BuiltinDocumentProperties" ascii //weight: 1
        $x_1_4 = "= \"p\" + ActiveSheet.PageSetup.CenterFooter" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Remcos_RVB_2147829214_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Remcos.RVB!MTB"
        threat_id = "2147829214"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Remcos"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "cAlHep.Open (rNJoz + \"\\afJNP.js\")" ascii //weight: 1
        $x_1_2 = "CreateObject(Cells(1, 1))" ascii //weight: 1
        $x_1_3 = "ActiveSheet.OLEObjects(1).Copy" ascii //weight: 1
        $x_1_4 = {53 75 62 20 57 6f 72 6b 62 6f 6f 6b 5f 41 63 74 69 76 61 74 65 28 29 0d 0a 43 61 6c 6c 20 67 55 41 71}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Remcos_DPC_2147832819_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Remcos.DPC!MTB"
        threat_id = "2147832819"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Remcos"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "=createobject(adlnw())setwyyss=iwxn.methods_(activesheet.pagesetup.leftheader)._" ascii //weight: 1
        $x_1_2 = "=fkldf(iwxn,wyyss)endsubfunctionlrljgz()" ascii //weight: 1
        $x_1_3 = "ggg,f8df00)setsjtn=ggg.execmethod_(zcfw(),f8df00)endfunctionprivatefunctionfjjdf()fjjdf=" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Remcos_DPD_2147833333_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Remcos.DPD!MTB"
        threat_id = "2147833333"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Remcos"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {3d 63 72 65 61 74 65 6f 62 6a 65 63 74 28 [0-5] 28 29 29 73 65 74 [0-5] 3d [0-4] 2e 6d 65 74 68 6f 64 73 5f 28 61 63 74 69 76 65 73 68 65 65 74 2e 70 61 67 65 73 65 74 75 70 2e 6c 65 66 74 68 65 61 64 65 72 29 2e 5f}  //weight: 1, accuracy: Low
        $x_1_2 = {3d 66 6b 6c 64 66 28 [0-4] 2c [0-5] 29 65 6e 64 73 75 62 66 75 6e 63 74 69 6f 6e}  //weight: 1, accuracy: Low
        $x_1_3 = {2b 66 6a 6a 64 66 28 29 65 6e 64 66 75 6e 63 74 69 6f 6e 66 75 6e 63 74 69 6f 6e 66 6b 6c 64 66 28 67 67 67 2c 66 38 64 66 30 30 29 73 65 74 73 6a 74 6e 3d 67 67 67 2e 65 78 65 63 6d 65 74 68 6f 64 5f 28 [0-4] 28 29 2c 66 38 64 66 30 30 29 65 6e 64 66 75 6e 63 74 69 6f 6e}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Remcos_JW_2147834424_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Remcos.JW!MTB"
        threat_id = "2147834424"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Remcos"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "://loft.london/vendor/phpunit/phpunit/src/Util/PHP/oder.exe" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Remcos_KI_2147839542_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Remcos.KI!MTB"
        threat_id = "2147839542"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Remcos"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Invoke-WebRequest -Uri \"\"https://transfer.sh/get/qIND4E/Rchnpc.exe\"\" -OutFile" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


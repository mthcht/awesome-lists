rule TrojanDownloader_O97M_Predator_AR_2147749609_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Predator.AR!MTB"
        threat_id = "2147749609"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Predator"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "8"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "#If Win64 Then" ascii //weight: 1
        $x_1_2 = "Private Declare PtrSafe Function WideCharToMultiByte Lib \"kernel32\" (ByVal CodePage As LongPtr, ByVal dwFlags As LongPtr," ascii //weight: 1
        $x_1_3 = "Private Declare PtrSafe Function MultiByteToWideChar Lib \"kernel32\" (ByVal CodePage As LongPtr, ByVal dwFlags As LongPtr," ascii //weight: 1
        $x_1_4 = {4f 6e 20 45 72 72 6f 72 20 5f [0-8] 52 65 73 75 6d 65 20 4e 65 78 74 [0-8] 43 61 6c 6c}  //weight: 1, accuracy: Low
        $x_1_5 = ".xls\"" ascii //weight: 1
        $x_1_6 = ".CreateElement(\"b64\")" ascii //weight: 1
        $x_1_7 = ".CREATE _" ascii //weight: 1
        $x_1_8 = {4e 75 6c 6c 2c 20 4e 75 6c 6c 2c 20 [0-16] 29}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Predator_AS_2147749691_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Predator.AS!MTB"
        threat_id = "2147749691"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Predator"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "7"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "#If Win64 Then" ascii //weight: 1
        $x_1_2 = "Private Declare PtrSafe Function WideCharToMultiByte Lib \"kernel32\" (ByVal CodePage As LongPtr, ByVal dwFlags As LongPtr," ascii //weight: 1
        $x_1_3 = "Private Declare PtrSafe Function MultiByteToWideChar Lib \"kernel32\" (ByVal CodePage As LongPtr, ByVal dwFlags As LongPtr," ascii //weight: 1
        $x_1_4 = {4f 6e 20 45 72 72 6f 72 20 5f [0-8] 52 65 73 75 6d 65 20 4e 65 78 74 [0-8] 43 61 6c 6c}  //weight: 1, accuracy: Low
        $x_1_5 = ".CreateElement(\"b64\")" ascii //weight: 1
        $x_1_6 = ".CREATE _" ascii //weight: 1
        $x_1_7 = {4e 75 6c 6c 2c 20 4e 75 6c 6c 2c 20 [0-16] 29}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Predator_AJ_2147749807_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Predator.AJ!MTB"
        threat_id = "2147749807"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Predator"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "kk(3, i) = Replace(kk(3, i), \"0x\", \"&h\")" ascii //weight: 1
        $x_1_2 = "Debug.Print \"16:\" & sh.Cells(j, 2) & \":\" & CStr(sh.Cells(j, 3)) & \"  \" & kk(3, i)" ascii //weight: 1
        $x_1_3 = "Debug.Print CStr(CLng(Replace(kk, \"0x\", \"&h\")))" ascii //weight: 1
        $x_1_4 = "Debug.Print rs(1) & \"    \";" ascii //weight: 1
        $x_1_5 = "MsgBox (\"???????????\")" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


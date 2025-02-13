rule TrojanDownloader_O97M_PowDow_YA_2147740787_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/PowDow.YA!MTB"
        threat_id = "2147740787"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "PowDow"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "ACAAaQBlAHgAKAAk" ascii //weight: 1
        $x_1_2 = "RABvAHcAbgBsAG8AYQBkAFMAdAByAGkAbgBnACgA" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_PowDow_YA_2147740787_1
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/PowDow.YA!MTB"
        threat_id = "2147740787"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "PowDow"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "output %USERPROFILE%\\Desktop\\Install.txt" ascii //weight: 1
        $x_1_2 = "cmd /c \"\"certutil.exe -dec##ode %USERPROFILE%\\D????esktop\\In?????stall.txt" ascii //weight: 1
        $x_1_3 = "I^n^s^t^a^l^l.txt&&call %var1%%var2%%var3" ascii //weight: 1
        $x_1_4 = "powershell.exe IEX $env:USERPROFILE\\Desktop\\Install.exe" ascii //weight: 1
        $x_1_5 = "Shell (qwert)" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_PowDow_YA_2147740787_2
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/PowDow.YA!MTB"
        threat_id = "2147740787"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "PowDow"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "strTemp = Chr(Val(\"&H\" + Mid(strFile, i, 2)))" ascii //weight: 1
        $x_1_2 = "CurFolder = \"C:\\Database" ascii //weight: 1
        $x_1_3 = "Set process = GetObject(ChrW(119) & ChrW(105) & ChrW(110) & ChrW(109)" ascii //weight: 1
        $x_1_4 = "process.create \"Rundll32 \" & Paramentrs & \",EnableAttr\"" ascii //weight: 1
        $x_1_5 = "d = CurFolder & \"\\\" & \"PuttyTel.exe\"" ascii //weight: 1
        $x_1_6 = "strTemp = Chr(Val(\"&H\" + Mid(hextostr, i, 2)))" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (4 of ($x*))
}


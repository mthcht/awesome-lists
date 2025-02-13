rule TrojanDropper_O97M_ZLoader_RZ_2147766867_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:O97M/ZLoader.RZ!MTB"
        threat_id = "2147766867"
        type = "TrojanDropper"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "ZLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "CreateTextFile(\"c:\\GoPhotonics\\Reddit.vbs" ascii //weight: 1
        $x_1_2 = "CreateObject(\"WScript.shell\").exec \"Regsvr32.exe -s c:\\GoPhotonics\\Waveplate.dll" ascii //weight: 1
        $x_1_3 = "CreateObject(\"WScript.shell\").exec \"%comspec% /c start /wait c:\\GoPhotonics\\Reddit.vbs" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDropper_O97M_ZLoader_AJJ_2147776510_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:O97M/ZLoader.AJJ!MTB"
        threat_id = "2147776510"
        type = "TrojanDropper"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "ZLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "fpxHqjl2ymMaaH5iPwri" ascii //weight: 1
        $x_1_2 = "KUpGfSAFd3nIeLl" ascii //weight: 1
        $x_1_3 = "C:\\Users\\User\\AppData\\Local\\Temp\\CVR7711.tmp.cvr" ascii //weight: 1
        $x_1_4 = "C:\\Users\\User\\AppData\\Local\\Temp\\wct837.vbs" ascii //weight: 1
        $x_1_5 = "rgq2g53" ascii //weight: 1
        $x_1_6 = "cswNvZRsrD" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


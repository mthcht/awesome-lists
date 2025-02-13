rule TrojanDropper_O97M_GravityRAT_2147727053_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:O97M/GravityRAT"
        threat_id = "2147727053"
        type = "TrojanDropper"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "GravityRAT"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Dir(Environ(\"APPDATA\") + \"\\image" ascii //weight: 1
        $x_1_2 = "= CreateObject(\"WScript.Shell\").ExpandEnvironmentStrings(\"%APPDATA%\") + \"\\temporary.zip\"" ascii //weight: 1
        $x_1_3 = "(Environ(\"APPDATA\") + \"\\temporary.zip\"), \"exe\"" ascii //weight: 1
        $x_1_4 = "schtasks /create /tn wordtest /tr %APPDATA%\\image" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


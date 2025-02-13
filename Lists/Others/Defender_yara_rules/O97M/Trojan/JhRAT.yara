rule Trojan_O97M_JhRAT_2147749487_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:O97M/JhRAT!MSR"
        threat_id = "2147749487"
        type = "Trojan"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "JhRAT"
        severity = "Critical"
        info = "MSR: Microsoft Security Response"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "https://drive.google.com/uc?export=download&id=1d-toE89QnN5ZhuNZIc2iF4-cbKWtk0FD" ascii //weight: 1
        $x_1_2 = "(\"Temp\") + \"\\\" + prcname + \".exe\"" ascii //weight: 1
        $x_1_3 = "Function ddfdsfdsfdww()" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


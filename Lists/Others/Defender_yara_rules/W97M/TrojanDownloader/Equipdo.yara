rule TrojanDownloader_W97M_Equipdo_A_2147690335_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:W97M/Equipdo.A"
        threat_id = "2147690335"
        type = "TrojanDownloader"
        platform = "W97M: Word 97, 2000, XP, 2003, 2007, and 2010 macros"
        family = "Equipdo"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "ChellEcsecute" ascii //weight: 1
        $x_1_2 = "MsgBox \"Este documento no es compatible con este" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_W97M_Equipdo_B_2147692247_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:W97M/Equipdo.B"
        threat_id = "2147692247"
        type = "TrojanDownloader"
        platform = "W97M: Word 97, 2000, XP, 2003, 2007, and 2010 macros"
        family = "Equipdo"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Call DownloadFile(\"http:" ascii //weight: 1
        $x_1_2 = "/bih/ss.exe\", \"e3e3e3.exe" ascii //weight: 1
        $x_1_3 = "MsgBox \"Este documento no es compatible con este" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_W97M_Equipdo_B_2147692247_1
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:W97M/Equipdo.B"
        threat_id = "2147692247"
        type = "TrojanDownloader"
        platform = "W97M: Word 97, 2000, XP, 2003, 2007, and 2010 macros"
        family = "Equipdo"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "XML.Open \"GET\", OPERA(\"XXX\"), False" ascii //weight: 1
        $x_1_2 = "FullSavePath = Environ(SavePath) & \"\\\" & OPERA(\"JKHDKSADS\")" ascii //weight: 1
        $x_1_3 = "MsgBox \"Este documento no es compatible con este equipo.\" & vbCrLf" ascii //weight: 1
        $x_1_4 = "\"cid\" = \"cid\" Then: OPERA = \"ht" ascii //weight: 1
        $x_1_5 = ".\" & \"ex\" & \"e\"" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


rule TrojanDownloader_W97M_Kidsoper_A_2147690793_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:W97M/Kidsoper.A"
        threat_id = "2147690793"
        type = "TrojanDownloader"
        platform = "W97M: Word 97, 2000, XP, 2003, 2007, and 2010 macros"
        family = "Kidsoper"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "BIGDICKMS = Environ(wtf(\"22@WTF@39@WTF@47@WTF@50\"))" ascii //weight: 1
        $x_1_2 = "BIGDICKSOPHOS = \"http://" ascii //weight: 1
        $x_1_3 = "BIGDICKKASPER = BIGDICKKASPER + BIGDICKSOPHOS" ascii //weight: 1
        $x_1_4 = "Shell BIGDICKKASPER, vbHide" ascii //weight: 1
        $x_1_5 = "arr = Split(shit, \"@WTF@\")" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (4 of ($x*))
}


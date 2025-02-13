rule TrojanDownloader_W97M_Bogavert_A_2147693012_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:W97M/Bogavert.gen!A"
        threat_id = "2147693012"
        type = "TrojanDownloader"
        platform = "W97M: Word 97, 2000, XP, 2003, 2007, and 2010 macros"
        family = "Bogavert"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "ChrW(104) & ChrW(116) & ChrW(116) & ChrW(112) & ChrW(58) & ChrW(47) & ChrW" ascii //weight: 1
        $x_1_2 = ".READYSTATE <> 4" ascii //weight: 1
        $x_1_3 = "= CreateObject(\"MSXML2.XMLHTTP\")" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


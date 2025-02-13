rule TrojanDownloader_W97M_Golroted_2147690666_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:W97M/Golroted"
        threat_id = "2147690666"
        type = "TrojanDownloader"
        platform = "W97M: Word 97, 2000, XP, 2003, 2007, and 2010 macros"
        family = "Golroted"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "/blob?download" ascii //weight: 1
        $x_1_2 = {3d 20 45 6e 76 69 72 6f 6e 28 22 54 65 6d 70 22 29 20 26 20 22 5c 22 20 26 20 22 [0-32] 2e 65 78 65 22}  //weight: 1, accuracy: Low
        $x_1_3 = "ge.tt/api/" ascii //weight: 1
        $x_1_4 = "& \".tt/api/" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

rule TrojanDownloader_W97M_Golroted_A_2147693013_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:W97M/Golroted.gen!A"
        threat_id = "2147693013"
        type = "TrojanDownloader"
        platform = "W97M: Word 97, 2000, XP, 2003, 2007, and 2010 macros"
        family = "Golroted"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "If URLDownloadToCacheFile(0, URL, szFileName, Len(szFileName), 0, 0) = 0 Then" ascii //weight: 1
        $x_1_2 = "TempPath = Replace(TempPath, Chr$(0), \"\")" ascii //weight: 1
        $x_1_3 = "= DownloadFile(\"http" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


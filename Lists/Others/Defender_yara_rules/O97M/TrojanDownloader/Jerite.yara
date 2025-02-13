rule TrojanDownloader_O97M_Jerite_A_2147742442_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Jerite.A"
        threat_id = "2147742442"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Jerite"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Left(\"Shellinshala\"," ascii //weight: 1
        $x_1_2 = "Jerk" ascii //weight: 1
        $x_1_3 = "Sprite" ascii //weight: 1
        $x_1_4 = "& \"\\s\" & \"e.\" &" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


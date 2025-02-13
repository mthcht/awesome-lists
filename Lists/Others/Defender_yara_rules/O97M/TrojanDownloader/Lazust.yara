rule TrojanDownloader_O97M_Lazust_YL_2147740722_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Lazust.YL"
        threat_id = "2147740722"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Lazust"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "21"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Declare PtrSafe Function WinExec Lib \"kernel32\"" ascii //weight: 1
        $x_1_2 = "auri=" ascii //weight: 1
        $x_20_3 = "czinfo.club/common.php" ascii //weight: 20
        $x_20_4 = "pegasusco.net/acide.php" ascii //weight: 20
        $x_20_5 = "smilekeepers.co/smile.php" ascii //weight: 20
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_20_*) and 1 of ($x_1_*))) or
            ((2 of ($x_20_*))) or
            (all of ($x*))
        )
}

rule TrojanDownloader_O97M_Lazust_YA_2147743608_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Lazust.YA"
        threat_id = "2147743608"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Lazust"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {61 6e 79 66 69 6c 65 2e 32 35 35 62 69 74 73 2e 63 6f 6d 2f 77 69 78 2f 64 6f 77 6e 6c 6f 61 64 3f 69 64 3d [0-32] 22 22 3e 3e [0-16] 2e 56 42 53}  //weight: 1, accuracy: Low
        $x_1_2 = {2e 56 42 53 20 20 26 20 74 49 4d 65 4f 55 54 20 [0-32] 20 26 20 [0-32] 2e 45 58 45}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


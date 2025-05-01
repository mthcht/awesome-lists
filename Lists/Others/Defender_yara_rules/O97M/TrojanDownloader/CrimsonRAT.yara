rule TrojanDownloader_O97M_CrimsonRAT_PC_2147940435_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/CrimsonRAT.PC!MTB"
        threat_id = "2147940435"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "CrimsonRAT"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "= CreateObject(\"Scripting.FileSystemObject\")" ascii //weight: 1
        $x_1_2 = "& Replace(\"Exac1.zi_sp\", \"_sp\", \"p\"), True" ascii //weight: 1
        $x_1_3 = {3d 20 45 6e 76 69 72 6f 6e 24 28 22 73 79 73 74 65 6d 72 6f 6f 74 22 29 20 26 20 52 65 70 6c 61 63 65 28 22 5c 4d 69 63 72 [0-2] 6f 73 6f 66 74 2e 4e 45 54 5c 46 72 61 [0-2] 6d 65 77 6f 72 6b 5c 76 [0-4] 2e [0-4] 22 2c 20 22 [0-2] 22 2c 20 22 22 29}  //weight: 1, accuracy: Low
        $x_2_4 = {53 68 65 6c 6c 20 [0-32] 26 [0-32] 26 20 22 2e 73 22 20 26 20 52 65 70 6c 61 63 65 28 22 63 72 5f 70 61 22 2c 20 22 5f 70 61 22 2c 20 22 22 29 2c 20 76 62 4e 6f 72 6d 61 6c 4e 6f 46 6f 63 75 73}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


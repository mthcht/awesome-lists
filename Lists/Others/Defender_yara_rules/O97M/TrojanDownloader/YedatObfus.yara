rule TrojanDownloader_O97M_YedatObfus_A_2147717169_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/YedatObfus.A"
        threat_id = "2147717169"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "YedatObfus"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "CreateObject(\"Scripting.FileSystemObject\")" ascii //weight: 1
        $x_1_2 = "CreateObject(\"WScript.Shell\")" ascii //weight: 1
        $x_1_3 = {20 41 73 20 53 74 72 69 6e 67 [0-15] 20 3d 20 [0-15] 2e 45 78 70 61 6e 64 45 6e 76 69 72 6f 6e 6d 65 6e 74 53 74 72 69 6e 67 73 28 [0-15] 28 41 72 72 61 79 28}  //weight: 1, accuracy: Low
        $x_1_4 = {49 66 20 4c 65 6e 28 44 69 72 28 [0-15] 2c 20 [0-15] 29 29 20 3d 20 30 20 54 68 65 6e 20 4d 6b 44 69 72 [0-16] 4e 65 78 74}  //weight: 1, accuracy: Low
        $x_1_5 = {53 65 74 20 [0-15] 20 3d 20 [0-15] 2e 43 72 65 61 74 65 54 65 78 74 46 69 6c 65 28 [0-15] 29}  //weight: 1, accuracy: Low
        $x_1_6 = {53 65 74 20 [0-15] 20 3d 20 [0-15] 2e 45 78 65 63 28 [0-15] 28 41 72 72 61 79 28}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


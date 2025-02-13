rule TrojanDownloader_O97M_Yedat_A_2147717170_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Yedat.A"
        threat_id = "2147717170"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Yedat"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "CreateObject(\"Scripting.FileSystemObject\")" ascii //weight: 1
        $x_1_2 = "CreateObject(\"WScript.Shell\")" ascii //weight: 1
        $x_1_3 = {20 41 73 20 53 74 72 69 6e 67 [0-15] 20 3d 20 [0-15] 2e 45 78 70 61 6e 64 45 6e 76 69 72 6f 6e 6d 65 6e 74 53 74 72 69 6e 67 73 28 22 25 41 50 50 44 41 54 41 25 5c 41 64 6f 62 65 5c [0-15] 2e 64 61 74 22 29}  //weight: 1, accuracy: Low
        $x_1_4 = {49 66 20 4c 65 6e 28 44 69 72 28 [0-15] 2c 20 [0-15] 29 29 20 3d 20 30 20 54 68 65 6e 20 4d 6b 44 69 72 [0-16] 4e 65 78 74}  //weight: 1, accuracy: Low
        $x_1_5 = {53 65 74 20 [0-15] 20 3d 20 [0-15] 2e 43 72 65 61 74 65 54 65 78 74 46 69 6c 65 28 [0-15] 29}  //weight: 1, accuracy: Low
        $x_1_6 = ".Exec(\"rundll32.exe" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


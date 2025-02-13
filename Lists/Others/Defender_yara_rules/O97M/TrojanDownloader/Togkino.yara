rule TrojanDownloader_O97M_Togkino_A_2147685981_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Togkino.A"
        threat_id = "2147685981"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Togkino"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "GoTo niko3" ascii //weight: 1
        $x_1_2 = {55 52 4c 44 6f 77 6e 6c 6f 61 64 54 6f 46 69 6c 65 20 30 2c 20 22 68 74 74 70 3a 2f 2f [0-21] 2e 65 78 65 22 2c 20 45 6e 76 69 72 6f 6e 28 22 54 45 4d 50 22 29 20 26 20 22 [0-9] 2e 65 78 65 22 2c 20 30 2c 20 30}  //weight: 1, accuracy: Low
        $x_1_3 = "Shell Environ(\"TEMP\") &" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Togkino_A_2147693014_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Togkino.gen!A"
        threat_id = "2147693014"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Togkino"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "Sub AutoOpen()" ascii //weight: 1
        $x_1_2 = "On Error Resume Next" ascii //weight: 1
        $x_1_3 = "0, \"http://" ascii //weight: 1
        $x_1_4 = {22 2c 20 45 6e 76 69 72 6f 6e 28 22 (41 50 50 44 41|54 45) 22 29 20 26 20 22 5c}  //weight: 1, accuracy: Low
        $x_1_5 = {53 68 65 6c 6c 20 45 6e 76 69 72 6f 6e 28 22 (41 50 50 44 41|54 45) 22 29 20 26 20 22 5c}  //weight: 1, accuracy: Low
        $x_1_6 = "Alias \"URLDownloadToFileA\"" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


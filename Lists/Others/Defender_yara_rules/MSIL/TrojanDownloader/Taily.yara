rule TrojanDownloader_MSIL_Taily_A_2147725136_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:MSIL/Taily.A!bit"
        threat_id = "2147725136"
        type = "TrojanDownloader"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Taily"
        severity = "Critical"
        info = "bit: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "\\Microsoft\\Windows\\CurrentVersion\\Run" wide //weight: 1
        $x_1_2 = "rgho.st/download/" wide //weight: 1
        $x_1_3 = "iplogger.com/" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (2 of ($x*))
}

rule TrojanDownloader_MSIL_Taily_B_2147725148_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:MSIL/Taily.B!bit"
        threat_id = "2147725148"
        type = "TrojanDownloader"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Taily"
        severity = "Critical"
        info = "bit: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {57 00 65 00 62 00 43 00 6c 00 69 00 65 00 6e 00 74 00 00 00 53 00 79 00 73 00 74 00 65 00 6d 00 2e 00 4e 00 65 00 74 00 00 00 44 00 6f 00 77 00 6e 00 6c 00 6f 00 61 00 64 00 46 00 69 00 6c 00 65 00}  //weight: 1, accuracy: High
        $x_1_2 = {66 00 61 00 73 00 74 00 69 00 6d 00 61 00 67 00 65 00 2e 00 78 00 79 00 7a 00 2f 00 [0-32] 2e 00 65 00 78 00 65 00}  //weight: 1, accuracy: Low
        $x_1_3 = {66 00 61 00 73 00 74 00 69 00 6d 00 61 00 67 00 65 00 2e 00 78 00 79 00 7a 00 2f 00 [0-32] 2e 00 6a 00 70 00 67 00 [0-2] 5c 00 53 00 63 00 72 00 65 00 65 00 6e 00 2e 00 6a 00 70 00 67 00}  //weight: 1, accuracy: Low
        $x_1_4 = {66 00 61 00 73 00 74 00 2d 00 69 00 6d 00 61 00 67 00 65 00 2e 00 78 00 79 00 7a 00 2f 00 [0-32] 2e 00 65 00 78 00 65 00}  //weight: 1, accuracy: Low
        $x_1_5 = {66 00 61 00 73 00 74 00 2d 00 69 00 6d 00 61 00 67 00 65 00 2e 00 78 00 79 00 7a 00 2f 00 [0-32] 2e 00 6a 00 70 00 67 00 [0-2] 5c 00 53 00 63 00 72 00 65 00 65 00 6e 00 2e 00 6a 00 70 00 67 00}  //weight: 1, accuracy: Low
        $x_1_6 = "NVDisplay.Display.exe" wide //weight: 1
        $x_2_7 = "\\steam\\Shell\\Open\\Command" wide //weight: 2
    condition:
        (filesize < 20MB) and
        (
            ((4 of ($x_1_*))) or
            ((1 of ($x_2_*) and 2 of ($x_1_*))) or
            (all of ($x*))
        )
}


rule TrojanDownloader_MSIL_Guplof_A_2147685670_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:MSIL/Guplof.A"
        threat_id = "2147685670"
        type = "TrojanDownloader"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Guplof"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {00 2e 00 67 00 75 00 6c 00 66 00 75 00 70 00 2e 00 63 00 6f 00 6d 00 2f 00 ?? 00 ?? 00 ?? 00 ?? 00 ?? 00 2e 00 6a 00 70 00 67 00 00 09 2e 00 65 00 78 00 65 00 00 09 2e 00 6a 00 70 00 67}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_MSIL_Guplof_B_2147685708_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:MSIL/Guplof.B"
        threat_id = "2147685708"
        type = "TrojanDownloader"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Guplof"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "13"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {00 62 76 62 6e 76 62 6e 66 76 68 66 67 68 66 67 00}  //weight: 1, accuracy: High
        $x_1_2 = {4c 6f 61 64 00 67 65 74 5f 45 6e 74 72 79 50 6f 69 6e 74}  //weight: 1, accuracy: High
        $x_1_3 = "MjAwMDA=" wide //weight: 1
        $x_10_4 = {68 00 74 00 74 00 70 00 3a 00 2f 00 2f 00 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 2e 00 67 00 75 00 6c 00 66 00 75 00 70 00 2e 00 63 00 6f 00 6d 00 2f 00 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 2e 00 74 00 78 00 74 00 3f 00 67 00 75 00 3d 00 [0-64] 26 00 65 00 3d 00 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 26 00 6e 00 3d 00 36 00 36 00 36 00 39 00 36 00 63 00 36 00 35 00 36 00 65 00 36 00 31 00 36 00 64 00 36 00 35 00}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


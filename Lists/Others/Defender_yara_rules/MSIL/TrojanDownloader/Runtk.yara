rule TrojanDownloader_MSIL_Runtk_A_2147697384_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:MSIL/Runtk.A"
        threat_id = "2147697384"
        type = "TrojanDownloader"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Runtk"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "14"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {68 00 74 00 74 00 70 00 73 00 3a 00 2f 00 2f 00 64 00 6f 00 63 00 73 00 2e 00 67 00 6f 00 6f 00 67 00 6c 00 65 00 2e 00 63 00 6f 00 6d 00 2f 00 75 00 63 00 3f 00 61 00 75 00 74 00 68 00 75 00 73 00 65 00 72 00 3d 00 30 00 26 00 69 00 64 00 3d 00 [0-32] 5f 00 [0-64] 26 00 65 00 78 00 70 00 6f 00 72 00 74 00 3d 00 64 00 6f 00 77 00 6e 00 6c 00 6f 00 61 00 64 00}  //weight: 5, accuracy: Low
        $x_5_2 = {68 00 74 00 74 00 70 00 3a 00 2f 00 2f 00 [0-64] 2e 00 74 00 6b 00 2f 00 69 00 70 00 2e 00 70 00 68 00 70 00 3f 00 65 00 78 00 3d 00}  //weight: 5, accuracy: Low
        $x_2_3 = {69 00 6d 00 61 00 67 00 65 00 [0-16] 2e 00 65 00 78 00 65 00}  //weight: 2, accuracy: Low
        $x_2_4 = {2e 00 70 00 6e 00 67 00 2e 00 65 00 78 00 65 00 90 00 00 00}  //weight: 2, accuracy: High
        $x_2_5 = "DownloadString" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_5_*) and 2 of ($x_2_*))) or
            (all of ($x*))
        )
}

rule TrojanDownloader_MSIL_Runtk_A_2147697624_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:MSIL/Runtk.gen!A"
        threat_id = "2147697624"
        type = "TrojanDownloader"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Runtk"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {64 00 6f 00 63 00 73 00 2e 00 67 00 6f 00 6f 00 67 00 6c 00 65 00 2e 00 63 00 6f 00 6d 00 2f 00 75 00 63 00 3f 00 61 00 75 00 74 00 68 00 75 00 73 00 65 00 72 00 3d 00 30 00 26 00 69 00 64 00 3d 00 30 00 42 00 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 26 00 65 00 78 00 70 00 6f 00 72 00 74 00 3d 00 64 00 6f 00 77 00 6e 00 6c 00 6f 00 61 00 64 00}  //weight: 1, accuracy: Low
        $x_1_2 = "/ip.php?ex=" wide //weight: 1
        $x_1_3 = {69 00 6d 00 61 00 67 00 65 00 [0-20] 2e 00 70 00 6e 00 67 00 2e 00 65 00 78 00 65 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


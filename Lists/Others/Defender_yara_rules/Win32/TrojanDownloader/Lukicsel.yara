rule TrojanDownloader_Win32_Lukicsel_A_2147629880_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Lukicsel.A"
        threat_id = "2147629880"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Lukicsel"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b 4d 0c 8b 09 8b 75 08 8b 36 4e a0 ?? ?? ?? ?? 30 04 31 e2 fb}  //weight: 1, accuracy: Low
        $x_1_2 = {83 c0 07 50 8b f0 b4 2f ac 3c 00 74 04 38 e0 75 f7}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_Win32_Lukicsel_A_2147629880_1
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Lukicsel.A"
        threat_id = "2147629880"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Lukicsel"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {42 48 75 f1 e8 05 00 80 74 11 ff}  //weight: 1, accuracy: Low
        $x_1_2 = {8a 54 3a ff 80 f2 ?? e8 ?? ?? ?? ?? 8b 55 f8 8b c6}  //weight: 1, accuracy: Low
        $x_1_3 = {66 b9 50 00 8b 55 fc}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


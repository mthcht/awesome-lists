rule TrojanDownloader_Win32_Egapel_A_2147628809_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Egapel.A"
        threat_id = "2147628809"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Egapel"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {0f 3f 07 0b c7 45}  //weight: 1, accuracy: High
        $x_1_2 = "%s?mac=%s&ver=%s&os=%s" ascii //weight: 1
        $x_1_3 = {80 f9 56 75 08 8a 10 40 80 fa 56 74 f8}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_Win32_Egapel_D_2147638587_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Egapel.D"
        threat_id = "2147638587"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Egapel"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {ff d6 3b c7 72 fa 5f 5e c3}  //weight: 1, accuracy: High
        $x_1_2 = {83 fe 2d 7e 05 83 ee 2d eb 03 83 c6 0f}  //weight: 1, accuracy: High
        $x_1_3 = {6a 7c 56 e8 ?? ?? 00 00 83 c4 0c (85 c0|3b c3)}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


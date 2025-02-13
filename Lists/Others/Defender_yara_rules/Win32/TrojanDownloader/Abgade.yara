rule TrojanDownloader_Win32_Abgade_A_2147632863_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Abgade.A"
        threat_id = "2147632863"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Abgade"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b 4d bc 89 44 8d c0 eb c8 6a ff 6a 01 8d 55 c0 52 6a ?? ff 15 ?? ?? ?? ?? 6a 00 a1}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_Win32_Abgade_B_2147632864_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Abgade.B"
        threat_id = "2147632864"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Abgade"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {ff d3 6a ff 6a 01 89 45 fc 8d 45 ec 50 6a ?? 5f 57 ff 15 ?? ?? ?? ?? 8d 75 ec ff 36 ff 15 ?? ?? ?? ?? 83 c6 04 4f}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


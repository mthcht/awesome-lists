rule TrojanDownloader_Win32_Otlard_A_2147622036_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Otlard.A"
        threat_id = "2147622036"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Otlard"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {32 45 ff 46 88 84 35 ?? ?? ff ff 8b c3 99 f7 f9 b1 03 8a c2 f6 e9}  //weight: 1, accuracy: Low
        $x_1_2 = {68 db d3 62 b5 89 45}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_Win32_Otlard_B_2147631473_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Otlard.B"
        threat_id = "2147631473"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Otlard"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {be 85 00 00 00 f7 fe 6b d2 03 03 ca 81 e1 ff 00 00 00}  //weight: 1, accuracy: High
        $x_1_2 = "GootkitSSO" wide //weight: 1
        $x_1_3 = {eb 01 46 80 3e 7c 75 fa}  //weight: 1, accuracy: High
        $x_1_4 = {6d 73 78 73 6c 74 2e 64 61 74 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (2 of ($x*))
}

rule TrojanDownloader_Win32_Otlard_D_2147658038_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Otlard.D"
        threat_id = "2147658038"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Otlard"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "?guid=[bot-guid]&proxyport=[proxyport]&platform=[bot-platfom]" ascii //weight: 1
        $x_1_2 = "\\%c([^\\%c\\%c]+)\\%c" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


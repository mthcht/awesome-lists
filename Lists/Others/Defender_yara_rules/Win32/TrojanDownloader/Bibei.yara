rule TrojanDownloader_Win32_Bibei_A_2147651871_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Bibei.A"
        threat_id = "2147651871"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Bibei"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {72 12 8b 03 0d 20 20 20 20 3d 68 74 74 70 0f 85}  //weight: 2, accuracy: High
        $x_1_2 = "tvmeinv.cn" ascii //weight: 1
        $x_1_3 = {eb 1b c7 86 10 01 00 00 ?? ?? ?? ?? eb 1b a1 ?? ?? ?? ?? 6a 0a 33 d2 59 f7 f1 83 fa 06}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule TrojanDownloader_Win32_Bibei_B_2147651872_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Bibei.B"
        threat_id = "2147651872"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Bibei"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {8a 04 37 8a c8 c0 e9 04 c0 e0 04 0a c8 47 f6 d1}  //weight: 1, accuracy: High
        $x_1_2 = {b0 74 51 53 66 c7 07 50 00 c6 44 24}  //weight: 1, accuracy: High
        $x_1_3 = {bb 58 ae 89 18 74 14 39 58 04}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (2 of ($x*))
}


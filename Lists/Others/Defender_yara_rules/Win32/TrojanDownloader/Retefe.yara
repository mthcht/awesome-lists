rule TrojanDownloader_Win32_Retefe_B_2147686251_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Retefe.B"
        threat_id = "2147686251"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Retefe"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "%d(d1b'u&v$k-d(mH" ascii //weight: 1
        $x_1_2 = {84 c9 74 10 8b d0 83 e2 03 8a 14 32 32 d1}  //weight: 1, accuracy: High
        $x_3_3 = {33 c0 89 46 0c c7 06 66 00 00 00 c7 46 04 67 00 00 00 c7 46 08 68 00 00 00 e9}  //weight: 3, accuracy: High
        $x_3_4 = {83 e8 01 75 ef 0c 00 8a 88 ?? ?? ?? ?? 30 88}  //weight: 3, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_3_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule TrojanDownloader_Win32_Retefe_C_2147686773_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Retefe.C"
        threat_id = "2147686773"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Retefe"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8d 64 24 00 8a ?? ?? ?? ?? ?? 30 ?? ?? ?? ?? ?? 83 ?? 01 75 ef}  //weight: 1, accuracy: Low
        $x_1_2 = {99 b9 15 00 00 00 f7 f9 83 c2 0a 0f b7 c2 69 c0 e8 03 00 00 c3}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


rule TrojanDownloader_Win32_Mafchek_A_2147637587_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Mafchek.A"
        threat_id = "2147637587"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Mafchek"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {72 75 6e 64 6c 6c 33 32 20 25 73 20 25 73 00 63 68 65 6b 00 68 74 74 70 3a 2f 2f 67 6f 6f 67 6c 65 2e 63 6f 6d}  //weight: 2, accuracy: High
        $x_1_2 = "SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon" ascii //weight: 1
        $x_1_3 = "Software\\Microsoft\\Office\\%s" ascii //weight: 1
        $x_1_4 = "/images/top2x.gif" ascii //weight: 1
        $x_1_5 = "I run in injected process" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((4 of ($x_1_*))) or
            ((1 of ($x_2_*) and 2 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule TrojanDownloader_Win32_Mafchek_B_2147637589_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Mafchek.B"
        threat_id = "2147637589"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Mafchek"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8d 45 dc e8 46 fd ff ff ff 75 dc ff 35 ?? ?? ?? ?? 68 ?? ?? ?? ?? 8d 45 e0 ba 04 00 00 00 e8}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


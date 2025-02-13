rule PWS_Win64_HighCount_A_2147910858_0
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:Win64/HighCount.A!dha"
        threat_id = "2147910858"
        type = "PWS"
        platform = "Win64: Windows 64-bit platform"
        family = "HighCount"
        severity = "Critical"
        info = "dha: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "\\PMIFeature.log" wide //weight: 2
        $x_2_2 = "\"%s\" /run%S%S%S%S" wide //weight: 2
        $x_1_3 = "\\ProgramData\\Microsoft\\Windows\\logs" wide //weight: 1
        $x_1_4 = "SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon" wide //weight: 1
        $x_1_5 = "SYSTEM\\CurrentControlSet\\Services\\LanmanWorkstation\\NetworkProvider" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 2 of ($x_1_*))) or
            ((2 of ($x_2_*))) or
            (all of ($x*))
        )
}

rule PWS_Win64_HighCount_B_2147910859_0
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:Win64/HighCount.B!dha"
        threat_id = "2147910859"
        type = "PWS"
        platform = "Win64: Windows 64-bit platform"
        family = "HighCount"
        severity = "Critical"
        info = "dha: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {60 00 00 00 05 81 a7 3c a3 a3 68 4a b4 58 1a 60 6b ab 8f d6 01 00 00 00 04 5d 88 8a eb 1c c9 11 9f e8 08 00 2b 10 48 60 02 00 00 00}  //weight: 1, accuracy: High
        $x_1_2 = "1f2a047b-96d8-488e-bc9b-1d5e00000000" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


rule PWS_Win32_Yokoyou_A_2147611521_0
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:Win32/Yokoyou.A"
        threat_id = "2147611521"
        type = "PWS"
        platform = "Win32: Windows 32-bit platform"
        family = "Yokoyou"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {8b d0 8a 83 ?? ?? ?? ?? 32 d0 8d 45 f4 e8 ?? ?? ff ff 8b 55 f4 8b c7 e8 ?? ?? ff ff 43 81 e3 07 00 00 80 79 05 4b 83 cb f8 43 ff 45 f8 4e 75 a1}  //weight: 2, accuracy: Low
        $x_1_2 = {43 5a 64 6c 6c 2e 64 6c 6c 00 53 74 61 72 74 48 6f 6f 6b 00 53 74 6f 70 48 6f 6f 6b 00 70 74 5f 6b 73 48 6f 6f 6b 00 70 74 5f 74 7a 48 6f 6f 6b}  //weight: 1, accuracy: High
        $x_1_3 = {41 74 78 74 5f 4e 61 6d 65 69 70 74 3d 00}  //weight: 1, accuracy: High
        $x_1_4 = {41 74 78 74 50 61 73 73 77 6f 72 64 3d 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((3 of ($x_1_*))) or
            ((1 of ($x_2_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule PWS_Win32_Yokoyou_B_2147646208_0
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:Win32/Yokoyou.B"
        threat_id = "2147646208"
        type = "PWS"
        platform = "Win32: Windows 32-bit platform"
        family = "Yokoyou"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "20"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "/ddos.jpg" ascii //weight: 10
        $x_10_2 = "8866.org" ascii //weight: 10
        $x_1_3 = "MiniSniffer" ascii //weight: 1
        $x_1_4 = "GameTroyHorseDetect" ascii //weight: 1
        $x_1_5 = "SOFTWARE\\ATerMinate" ascii //weight: 1
        $x_1_6 = "Active%c%c%c%c." ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_10_*))) or
            (all of ($x*))
        )
}


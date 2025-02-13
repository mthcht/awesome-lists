rule Backdoor_Win32_Otlard_A_2147631470_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Otlard.A"
        threat_id = "2147631470"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Otlard"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {c6 45 f8 67 c6 45 f9 6f c6 45 fa 6f c6 45 fb 74 c6 45 fc 6b}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_Win32_Otlard_B_2147632716_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Otlard.B"
        threat_id = "2147632716"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Otlard"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {ff 70 04 ff 70 0c e8 ?? ?? ?? ?? 39 75 0c 89 77 58 0f 94 c0}  //weight: 2, accuracy: Low
        $x_2_2 = {74 07 b8 01 00 00 00 eb 1d 68 ?? ?? ?? ?? 8b 4d 08 51 ff 15}  //weight: 2, accuracy: Low
        $x_1_3 = {75 0e ff 45 fc 8b 45 fc 83 c6 08 3b 45 f0 72 b3 ff 75 f4}  //weight: 1, accuracy: High
        $x_1_4 = {2f 62 6f 6f 74 73 74 72 61 70 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 1 of ($x_1_*))) or
            ((2 of ($x_2_*))) or
            (all of ($x*))
        )
}


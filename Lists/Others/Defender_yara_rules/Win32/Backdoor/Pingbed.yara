rule Backdoor_Win32_Pingbed_A_2147629381_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Pingbed.A"
        threat_id = "2147629381"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Pingbed"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {68 ff 0f 1f 00 ff 15 ?? ?? ?? ?? 8b f8 85 ff 74 ?? 6a 00 57 ff 15 ?? ?? ?? ?? 8b d8 85 db 75 ?? 68 f4 01 00 00 ff 15}  //weight: 2, accuracy: Low
        $x_2_2 = {68 fb 1f 00 00 50 ff 75 ?? ff 15 ?? ?? ?? ?? 83 7d ?? 00 74}  //weight: 2, accuracy: Low
        $x_1_3 = {25 73 20 25 73 00}  //weight: 1, accuracy: High
        $x_1_4 = {4b 69 6c 6c 69 6e 67 20 70 72 6f 63 65 73 73 20 25 73 20 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 2 of ($x_1_*))) or
            ((2 of ($x_2_*))) or
            (all of ($x*))
        )
}

rule Backdoor_Win32_Pingbed_B_2147654533_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Pingbed.B"
        threat_id = "2147654533"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Pingbed"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {4b 69 6c 6c 69 6e 67 20 70 72 6f 63 65 73 73 20 25 64 20 00 4b 69 6c 6c 69 6e 67 20 70 72 6f 63 65 73 73 20 25 73}  //weight: 1, accuracy: High
        $x_1_2 = {3c 0a 75 0a 80 7d ?? 0d 74 04 c6 01 0d 41 88 01 88 45 00 8b 45 ?? 41 40 89 45 02 3b 45 ?? 72 dc}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


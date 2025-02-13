rule PWS_Win32_Buzbav_B_2147607896_0
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:Win32/Buzbav.B"
        threat_id = "2147607896"
        type = "PWS"
        platform = "Win32: Windows 32-bit platform"
        family = "Buzbav"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {56 57 b9 40 00 00 00 33 c0 8d 7c 24 ?? c6 44 24 ?? 00 f3 ab 66 ab aa b9 ff 01 00 00 33 c0 8d bc 24 ?? 01 00 00 c6 84 24 ?? 01 00 00 00 f3 ab 66 ab aa b9 ?? 00 00 00}  //weight: 1, accuracy: Low
        $x_1_2 = {43 3a 5c 57 49 4e 44 4f 57 53 5c 73 79 73 74 65 6d 33 32 5c [0-16] 2e 64 6c 6c [0-16] 53 45 52 56 45 52 [0-21] 40 65 78 69 74 00 40 64 65 6c [0-48] 2e 61 71 71}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule PWS_Win32_Buzbav_B_2147607896_1
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:Win32/Buzbav.B"
        threat_id = "2147607896"
        type = "PWS"
        platform = "Win32: Windows 32-bit platform"
        family = "Buzbav"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {53 55 56 57 33 ff 68 ?? ?? 40 00 68 ?? ?? 40 00 c7 05 ?? ?? 40 00 30 00 00 00 c7 05 ?? ?? 40 00 02 00 00 00 c7 05 ?? ?? 40 00 05 00 00 00 89 3d ?? ?? 40 00 89 3d ?? ?? 40 00 89 3d ?? ?? 40 00 89 3d ?? ?? 40 00 ff 15 ?? ?? 40 00 8b 1d ?? ?? 40 00 bd 04 00 00 00 68 ?? ?? 40 00 50 a3 ?? ?? 40 00 89 2d ?? ?? 40 00 ff d3 a1 ?? ?? 40 00 33 f6 3b c5 75 ?? 8b 2d ?? ?? 40 00 57 68 ?? ?? 40 00}  //weight: 1, accuracy: Low
        $x_1_2 = {43 3a 5c 57 49 4e 44 4f 57 53 5c 73 79 73 74 65 6d 33 32 5c [0-16] 2e 64 6c 6c [0-5] 50 72 6f 67 4d 61 6e [0-5] 58 59 74 65 73 74}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule PWS_Win32_Buzbav_B_2147607897_0
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:Win32/Buzbav.B"
        threat_id = "2147607897"
        type = "PWS"
        platform = "Win32: Windows 32-bit platform"
        family = "Buzbav"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {57 57 50 56 ff 15 ?? ?? 00 10 8d 44 24 ?? 57 50 8d [0-6] 68 00 02 00 00 51 56 ff 15 ?? ?? 00 10 [0-8] 8b 35 ?? ?? 00 10 [0-5] 8d [0-6] 68 ?? ?? 00 10 52 ff d6 83 c4 08 85 c0 75 09 ?? 81 ?? fe 01 00 00}  //weight: 2, accuracy: Low
        $x_1_2 = "a=%s&p=%s&g=%s&s=%s&n=%s&l=%s" ascii //weight: 1
        $x_1_3 = "BZBAVSMT" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}


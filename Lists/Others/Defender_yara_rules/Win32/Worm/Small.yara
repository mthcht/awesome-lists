rule Worm_Win32_Small_AF_2147630897_0
{
    meta:
        author = "defender2yara"
        detection_name = "Worm:Win32/Small.AF"
        threat_id = "2147630897"
        type = "Worm"
        platform = "Win32: Windows 32-bit platform"
        family = "Small"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {4c 45 00 00 61 6e 67 65 6c 00 00 00 70 61 73 73 77 6f 72 64 00 00 00 00 70 61 73 73 77 64}  //weight: 1, accuracy: High
        $x_1_2 = {62 61 72 72 79 73 77 6f 72 6c 64 2e 63 6f 6d 00 00 00 00 44 41 54 41}  //weight: 1, accuracy: High
        $x_1_3 = {48 45 4c 4f 20 3c 00 00 32 30 39 2e 38 35 2e 31 33 33 2e 31 31 34 00 00 57 55 70 64 61 74 65}  //weight: 1, accuracy: High
        $x_1_4 = {68 49 6e 66 6f 30 38 30 32 40 67 6d 61 69 6c 2e 63 6f 6d 00 00 00 00 74 65 73 74 31 32 33 34}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

rule Worm_Win32_Small_GD_2147940797_0
{
    meta:
        author = "defender2yara"
        detection_name = "Worm:Win32/Small.GD!MTB"
        threat_id = "2147940797"
        type = "Worm"
        platform = "Win32: Windows 32-bit platform"
        family = "Small"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {34 44 47 47 59 9c 31 cb b5 19 d1 31 0d ?? ?? ?? ?? 19 ec e4 52 2a c2 2c a5 6c 52 e2}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


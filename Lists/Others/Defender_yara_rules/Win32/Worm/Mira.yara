rule Worm_Win32_Mira_C_2147734906_0
{
    meta:
        author = "defender2yara"
        detection_name = "Worm:Win32/Mira.C!bit"
        threat_id = "2147734906"
        type = "Worm"
        platform = "Win32: Windows 32-bit platform"
        family = "Mira"
        severity = "Critical"
        info = "bit: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {c6 85 79 ff ff ff 3a c6 85 7a ff ff ff 5c c6 85 7b ff ff ff 4d c6 85 7c ff ff ff 69 c6 85 7d ff ff ff 72 c6 85 7e ff ff ff 61}  //weight: 1, accuracy: High
        $x_1_2 = "Saaaalamm" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Worm_Win32_Mira_A_2147750009_0
{
    meta:
        author = "defender2yara"
        detection_name = "Worm:Win32/Mira.A!ibt"
        threat_id = "2147750009"
        type = "Worm"
        platform = "Win32: Windows 32-bit platform"
        family = "Mira"
        severity = "Critical"
        info = "ibt: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Application Data\\Saaaalamm\\Mira.h" ascii //weight: 1
        $x_1_2 = {c6 85 79 ff ff ff 3a c6 85 7a ff ff ff 5c c6 85 7b ff ff ff 4d c6 85 7c ff ff ff 69 c6 85 7d ff ff ff 72 c6 85 7e ff ff ff 61}  //weight: 1, accuracy: High
        $x_1_3 = {80 bc 28 78 ff ff ff 65 75 4b 0f bf 05 14 20 44 00 80 bc 28 77 ff ff ff 78 75 3a 0f bf 05 14 20 44 00 80 bc 28 76 ff ff ff 65 75 29 0f bf 05 14 20 44 00 80 bc 28 75 ff ff ff 2e 75 18 0f bf 05 14 20 44 00 80 bc 28 74 ff ff ff 20}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Worm_Win32_Mira_J_2147750129_0
{
    meta:
        author = "defender2yara"
        detection_name = "Worm:Win32/Mira.J!ibt"
        threat_id = "2147750129"
        type = "Worm"
        platform = "Win32: Windows 32-bit platform"
        family = "Mira"
        severity = "Critical"
        info = "ibt: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "Saaaalamm" ascii //weight: 1
        $x_1_2 = "\\Mira.h" ascii //weight: 1
        $x_1_3 = {01 d0 8d 14 85 00 00 00 00 01 d0 29 c1 89 c8 04 61 88 03 8d 45 f8 ff 00 eb b8}  //weight: 1, accuracy: High
        $x_1_4 = {c7 44 24 1c 00 00 00 00 c7 44 24 18 00 00 00 00 c7 44 24 14 10 00 00 00 c7 44 24 10 00 00 00 00 c7 44 24 0c 00 00 00 00 c7 44 24 08 00 00 00 00 c7 44 24 04 00 00 00 00 c7 04 24 ?? ?? ?? ?? e8}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


rule Trojan_Win32_UpperCider_A_2147730356_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/UpperCider.A!dha"
        threat_id = "2147730356"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "UpperCider"
        severity = "Critical"
        info = "dha: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {56 69 72 74 c7 45 ?? 75 61 6c 50 c7 45 ?? 72 6f 74 65 [0-2] c7 45 ?? 63 74 [0-6] c7 45 ?? 6b 65 72 6e c7 45 ?? 65 6c 33 32 c7 45 ?? 2e 64 6c 6c [0-6] ff 15 ?? ?? ?? ?? 50 ff 15}  //weight: 1, accuracy: Low
        $x_1_2 = {5e 8a 10 30 11 40 41 4e 75 ?? 4f 75 02 00 6a}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_UpperCider_B_2147730357_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/UpperCider.B!dha"
        threat_id = "2147730357"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "UpperCider"
        severity = "Critical"
        info = "dha: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "16"
        strings_accuracy = "Low"
    strings:
        $x_3_1 = "xlAutoOpen" ascii //weight: 3
        $x_3_2 = "RegisterXLL.dll" ascii //weight: 3
        $x_5_3 = {01 00 00 0f b6 b8 01 01 00 00 0f b6 f2 0f b6 1c 06 02 1c 07 fe c2 0f b6 f3 0f b6 1c 06 8b 75 ?? 32 1c 0e 88 90 00 01 00 00 0f b6 fa 0f b6 14 07 00 90 01 01 00 00 0f b6 b0 01 01 00 00}  //weight: 5, accuracy: Low
        $x_5_4 = {8a 14 07 88 59 01 0f b6 1c 06 88 1c 07 88 14 06 8a 90 00 01 00 00 0f b6 b8 01 01 00 00 0f b6 f2 0f b6 1c 06 02 1c 07 83 c1 03 0f b6 f3 0f b6 1c 06 8b 75 ?? 32 5c 0e fd ff 4d fc 88 59 ff 0f 85}  //weight: 5, accuracy: Low
        $x_10_5 = {6a 00 68 14 04 00 03 6a 00 6a 00 6a 00 8d [0-6] 6a 00 ff 15 ?? ?? ?? ?? 85 c0 74 ?? ?? ?? ?? ?? 6a 40 68 00 30 00 00 57 6a 00 52 ff 15 [0-27] 6a 00 57 50 56 51 ff 15 ?? ?? ?? ?? 85 c0 [0-8] 6a 00 6a 00 6a 00 56 6a 00 6a 00 52 ff 15}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_5_*) and 2 of ($x_3_*))) or
            ((1 of ($x_10_*) and 2 of ($x_3_*))) or
            ((1 of ($x_10_*) and 1 of ($x_5_*) and 1 of ($x_3_*))) or
            ((1 of ($x_10_*) and 2 of ($x_5_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_UpperCider_C_2147730358_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/UpperCider.C!dha"
        threat_id = "2147730358"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "UpperCider"
        severity = "Critical"
        info = "dha: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_3_1 = "xlAutoOpen" ascii //weight: 3
        $x_3_2 = "RegisterXLL.dll" ascii //weight: 3
        $x_5_3 = {ff ff ff 43 72 65 61 c7 45 ?? 74 65 52 65 c7 45 ?? 6d 6f 74 65 c7 45 ?? 54 68 72 65 66 c7 45 ?? 61 64 c6 45 ?? 00 c7 45 ?? ?? 65 72 6e c7 45 ?? 65 6c 33 32 c7 45 ?? 2e 64 6c 6c c6 45 ?? 00 ff ?? 50 ff ?? 68 04 01 00 00 8d 95 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 8b f0 ff 95}  //weight: 5, accuracy: Low
        $x_5_4 = {83 e8 04 83 c1 04 83 c7 04 83 f8 04 73 ?? 85 c0 74 ?? 8a 19 3a 1f 75 ?? 83 f8 01 76 ?? 8a 59 01 3a 5f 01 75 ?? 83 f8 02 76 ?? 8a 41 02 3a 47 02 75 ?? 5b b8 ?? ?? ?? ?? 5f 2b c6}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_5_*) and 2 of ($x_3_*))) or
            ((2 of ($x_5_*))) or
            (all of ($x*))
        )
}


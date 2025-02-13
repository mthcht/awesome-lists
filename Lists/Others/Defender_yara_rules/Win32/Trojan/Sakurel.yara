rule Trojan_Win32_Sakurel_C_2147711948_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Sakurel.C!dha"
        threat_id = "2147711948"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Sakurel"
        severity = "Critical"
        info = "dha: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {c6 40 01 00 59 5b 6a 69 68 70 2e 6d 73 68 73 65 74 75 54 ff 35 ?? ?? ?? ?? e8}  //weight: 1, accuracy: Low
        $x_1_2 = {31 c0 8a 04 0b 3c 00 74 09 38 d0 74 05 30 d0 88 04 0b 83 f9 00 74 03}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Sakurel_C_2147711948_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Sakurel.C!dha"
        threat_id = "2147711948"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Sakurel"
        severity = "Critical"
        info = "dha: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8d 0c 02 8a 01 84 c0 74 08 3c ?? 74 04 34 ?? 88 01 42 3b 55 0c 7c}  //weight: 1, accuracy: Low
        $x_1_2 = {ff 74 24 10 b2 54 e8 ?? ?? ?? ?? ff 74 24 14 80 c2 f8 8b f0 e8 ?? ?? ?? ?? ff 74 24 18 b2 45 8b d8}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Sakurel_B_2147711949_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Sakurel.B!dha"
        threat_id = "2147711949"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Sakurel"
        severity = "Critical"
        info = "dha: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {25 64 5f 6f 66 5f 25 64 5f 66 6f 72 5f 25 73 5f 6f 6e 5f 25 73 00}  //weight: 1, accuracy: High
        $x_1_2 = {2f 63 20 70 69 6e 67 20 31 32 37 2e 30 2e 30 2e 31 20 26 20 64 65 6c 20 2f 71 20 22 25 73 22 00}  //weight: 1, accuracy: High
        $x_1_3 = {3f 70 68 6f 74 6f 69 64 3d 00}  //weight: 1, accuracy: High
        $x_2_4 = {68 f4 01 00 00 ff 15 ?? ?? ?? ?? 81 c3 00 90 01 00 3b 9d ?? ?? ff ff 0f 86 ?? ?? ff ff}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((3 of ($x_1_*))) or
            ((1 of ($x_2_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_Sakurel_B_2147711949_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Sakurel.B!dha"
        threat_id = "2147711949"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Sakurel"
        severity = "Critical"
        info = "dha: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {25 64 5f 6f 66 5f 25 64 5f 66 6f 72 5f 25 73 5f 6f 6e 5f 25 73 00}  //weight: 1, accuracy: High
        $x_1_2 = {2f 63 20 70 69 6e 67 20 31 32 37 2e 30 2e 30 2e 31 20 26 20 64 65 6c 20 2f 71 20 22 25 73 22 00}  //weight: 1, accuracy: High
        $x_1_3 = {3f 72 65 73 69 64 3d 25 64 [0-15] 26 70 68 6f 74 6f 69 64 3d 00}  //weight: 1, accuracy: Low
        $x_1_4 = {68 f4 01 00 00 ff 15 ?? ?? ?? ?? 81 c5 00 90 01 00 3b eb 0f 86}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Sakurel_D_2147711950_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Sakurel.D!dha"
        threat_id = "2147711950"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Sakurel"
        severity = "Critical"
        info = "dha: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {25 64 5f 6f 66 5f 25 64 5f 66 6f 72 5f 25 73 5f 6f 6e 5f 25 73 00}  //weight: 1, accuracy: High
        $x_1_2 = {3f 72 65 73 69 64 3d 25 64 [0-15] 26 70 68 6f 74 6f 69 64 3d 00}  //weight: 1, accuracy: Low
        $x_1_3 = {8a 0c 10 84 c9 74 0b 80 f9 56 74 06 80 f1 56 88 0c 10 40 3b 45 0c 7c e8}  //weight: 1, accuracy: High
        $x_1_4 = "cmd.exe /c rundll32 \"%s\" Player %s" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}


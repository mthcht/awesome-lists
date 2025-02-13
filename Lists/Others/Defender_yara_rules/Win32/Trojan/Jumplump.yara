rule Trojan_Win32_Jumplump_A_2147788463_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Jumplump.A!dha"
        threat_id = "2147788463"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Jumplump"
        severity = "Critical"
        info = "dha: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {66 3d 4d 5a e9 ?? ?? ?? ff}  //weight: 1, accuracy: Low
        $x_1_2 = {48 81 ee 02 10 00 00 e9 ?? ?? ?? (ff|00)}  //weight: 1, accuracy: Low
        $x_1_3 = {48 81 ec 10 04 00 00 e9}  //weight: 1, accuracy: High
        $x_1_4 = {41 bf 38 68 0d 16}  //weight: 1, accuracy: High
        $x_1_5 = {41 bf aa c5 e2 5d}  //weight: 1, accuracy: High
        $x_1_6 = {41 bf 08 87 1d 60}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (5 of ($x*))
}

rule Trojan_Win32_Jumplump_F_2147826453_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Jumplump.F!dha"
        threat_id = "2147826453"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Jumplump"
        severity = "Critical"
        info = "dha: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {48 81 ee 02 10 00 00 e9 66 3d 4d 5a e9 0f 85}  //weight: 1, accuracy: Low
        $x_1_2 = {ba 60 00 00 00 e9 65 48 8b 12 e9}  //weight: 1, accuracy: Low
        $x_1_3 = {b8 60 00 00 00 e9 31 c9 e9 ff c1 e9 89 0c 02 e9}  //weight: 1, accuracy: Low
        $x_1_4 = {83 fa 01 e9 0f 85 ?? ?? ?? ?? e9 41 54 e9 41 57 e9}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win32_Jumplump_H_2147827823_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Jumplump.H!dha"
        threat_id = "2147827823"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Jumplump"
        severity = "Critical"
        info = "dha: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {41 bf 10 e1 8a c3 e9}  //weight: 2, accuracy: High
        $x_2_2 = {41 bf 5d 44 11 ff e9}  //weight: 2, accuracy: High
        $x_2_3 = {41 bf 4c 77 d6 07 e9}  //weight: 2, accuracy: High
        $x_2_4 = {41 bf 40 de ce 72 e9}  //weight: 2, accuracy: High
        $x_2_5 = {41 bf 49 f7 02 78 e9}  //weight: 2, accuracy: High
        $x_2_6 = {41 bf 6c b0 85 db e9}  //weight: 2, accuracy: High
        $x_1_7 = {ba 60 00 00 00 e9}  //weight: 1, accuracy: High
        $x_1_8 = {65 48 8b 12 e9}  //weight: 1, accuracy: High
        $x_1_9 = {48 81 ee 02 10 00 00 e9}  //weight: 1, accuracy: High
        $x_1_10 = {66 3d 4d 5a e9}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((4 of ($x_1_*))) or
            ((1 of ($x_2_*) and 2 of ($x_1_*))) or
            ((2 of ($x_2_*))) or
            (all of ($x*))
        )
}


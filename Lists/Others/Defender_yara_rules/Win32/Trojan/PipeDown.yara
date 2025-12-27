rule Trojan_Win32_PipeDown_A_2147957199_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/PipeDown.A!dha"
        threat_id = "2147957199"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "PipeDown"
        severity = "Critical"
        info = "dha: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b 8e f8 04 00 00 0f b6 c3 8d 14 19 [0-1] 8a 04 08 30 82 00 01 00 00 [0-1] 8b 86 fc 04 00 00 [0-6] 3b d8 72}  //weight: 1, accuracy: Low
        $x_1_2 = {c8 06 00 00 8d 14 ?? 0f b6 cb 43 8a 04 01 30 82 ?? ?? ?? ?? 3b ?? 72 e6}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_PipeDown_A_2147957199_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/PipeDown.A!dha"
        threat_id = "2147957199"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "PipeDown"
        severity = "Critical"
        info = "dha: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {0f b6 01 8d 49 01 30 04 96 0f b6 41 03 30 44 95 ed 0f b6 41 07 30 04 93 0f b6 41 0b 30 04 97 42 83 fa 04 72 db}  //weight: 1, accuracy: High
        $x_1_2 = {0f b6 44 8d ec 8d 52 01 32 04 0e 88 44 8d ec 0f b6 44 0e 04 30 44 8d ed 0f b6 42 fb 30 44 8d ee 0f b6 42 ff 30 44 8d ef 41 83 f9 04 72 d2}  //weight: 1, accuracy: High
        $x_1_3 = {43 00 3a 00 5c 00 50 00 72 00 6f 00 67 00 72 00 61 00 ?? ?? 44 00 61 00 74 00 61 00 5c 00}  //weight: 1, accuracy: Low
        $x_1_4 = {53 00 6f 00 66 00 74 00 77 00 61 00 72 00 65 00 5c 00 4d 00 69 00 63 00 72 00 6f 00 73 00 6f 00 66 00 ?? ?? 5c 00 57 00 69 00 6e 00 64 00 6f 00 77 00 73 00 5c 00 43 00 75 00 72 00 72 00 65 00 6e 00 74 00 56 00 65 00 72 00 73 00 69 00 6f 00 6e 00 5c 00 52 00 75 00 6e 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_PipeDown_B_2147957200_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/PipeDown.B!dha"
        threat_id = "2147957200"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "PipeDown"
        severity = "Critical"
        info = "dha: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {0f be 04 16 33 c8 8b 55 08 8b 82 ?? ?? ?? ?? 8b 55 fc 88 8c 10 00 01 00 00 eb 9f}  //weight: 1, accuracy: Low
        $x_1_2 = {0f be 14 10 33 ca 8b 45 14 03 45 fc 88 08 eb c1}  //weight: 1, accuracy: High
        $x_1_3 = {8b 55 f8 0f af 55 f4 0f be 45 ff 03 d0 89 55 f8 eb b7}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


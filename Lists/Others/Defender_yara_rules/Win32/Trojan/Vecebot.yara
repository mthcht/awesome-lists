rule Trojan_Win32_Vecebot_A_2147639806_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Vecebot.A"
        threat_id = "2147639806"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Vecebot"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {74 2a 8d 83 00 18 00 00 50 8d 8b 00 10 00 00 51 8d 93 00 08 00 00 52}  //weight: 1, accuracy: High
        $x_1_2 = {50 68 fa 00 00 00 56}  //weight: 1, accuracy: High
        $x_1_3 = {72 00 75 00 6e 00 64 00 6c 00 6c 00 33 00 32 00 2e 00 65 00 78 00 65 00 00 00 00 00 63 00 6f 00 6e 00 66 00 69 00 72 00 6d 00 5f 00 65 00 78 00 70 00 6c 00 6f 00 72 00 65 00 72 00 00 00 00 00 44 00 48 00 43 00 50 00 20 00 56 00 65 00 72 00 73 00 69 00 6f 00 6e 00 20 00 36 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Vecebot_A_2147639806_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Vecebot.A"
        threat_id = "2147639806"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Vecebot"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {25 00 73 00 2e 00 6d 00 75 00 69 00 00 00 00 00 25 00 73 00 2e 00 6e 00 65 00 77 00 00 00 00 00 63 00 6f 00 6e 00 66 00 69 00 72 00 6d 00 5f 00 65 00 78 00 70 00 6c 00 6f 00 72 00 65 00 72 00}  //weight: 1, accuracy: High
        $x_1_2 = {77 00 75 00 61 00 75 00 73 00 65 00 72 00 76 00 63 00 6f 00 6d 00 00 00 73 00 65 00 74 00 68 00 63 00 2e 00 65 00 78 00 65 00}  //weight: 1, accuracy: High
        $x_1_3 = {6a 04 6a 5d b9 ?? ?? ?? ?? 8d b5 ?? ?? ?? ?? e8 ?? ?? ?? ?? 6a 04 68 ?? 90 04 00 b9 ?? ?? ?? ?? 8d b5 ?? ?? ?? ?? e8 ?? ?? ?? ?? 6a 04 68 f2 7a 00 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


rule Trojan_Win32_Sofacy_A_2147725787_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Sofacy.A!dha"
        threat_id = "2147725787"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Sofacy"
        severity = "Critical"
        info = "dha: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "20"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {8b c7 33 d2 f7 76 0c 8b 46 08 8a 04 02 32 44 39 ff 32 04 39 88 04 1f 4f}  //weight: 10, accuracy: High
        $x_10_2 = {52 65 67 53 66 c7 ?? ?? 65 74 c6 45 be 56 88 55 bf 88 4d c0 c7 ?? ?? 75 65 45 78 66 c7 ?? ?? 57 00}  //weight: 10, accuracy: Low
        $x_10_3 = {65 6e 4b 65 c7 ?? ?? 79 45 78 57 88 5d d5}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (2 of ($x*))
}

rule Trojan_Win32_Sofacy_B_2147725788_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Sofacy.B!dha"
        threat_id = "2147725788"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Sofacy"
        severity = "Critical"
        info = "dha: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "20"
        strings_accuracy = "High"
    strings:
        $x_10_1 = {83 7d fc 00 b0 20 6a 40 0f b6 c0 59 0f 45 c1 8b e5}  //weight: 10, accuracy: High
        $x_10_2 = "2@{gG,?B\"k" ascii //weight: 10
        $x_10_3 = {79 25 09 09 22 40 0c 70 0c 0f 5e 2c}  //weight: 10, accuracy: High
    condition:
        (filesize < 20MB) and
        (2 of ($x*))
}


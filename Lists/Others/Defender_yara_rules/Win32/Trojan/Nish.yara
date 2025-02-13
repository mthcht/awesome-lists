rule Trojan_Win32_Nish_A_2147643185_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Nish.A"
        threat_id = "2147643185"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Nish"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "TIEAdvBHOFactory" ascii //weight: 1
        $x_1_2 = {36 41 37 42 45 44 30 32 45 31 34 44 36 41 32 45 31 34 44 36 41 45 41 32 45 31 34 44 36 41 45 41 32 45 31 34 44 36 41 45 41 32 45 31 34 44 36 41 45 44 30 32 45 31 34 44 36 41 44 36 41 37 42 45 44 30 32 45 31 34 44 00}  //weight: 1, accuracy: High
        $x_1_3 = {54 49 45 4d 6f 6e 69 74 6f 72 8d 40 00 ff ff ff ff ?? 00 00 00 68 74 74 70 3a 2f 2f 77 77 77 2e}  //weight: 1, accuracy: Low
        $x_1_4 = {45 00 01 73 2a a1 ?? ?? 45 00 50 68 54 ?? 45 00 68 ?? ?? 45 00 6a 00 6a 02 6a 01 8b 0d ?? ?? 45 00 8b 09 b2 01 a1 ?? ?? 45 00 e8}  //weight: 1, accuracy: Low
        $x_1_5 = {8d 85 7b ff ff ff 50 6a 00 e8 ?? ?? fa ff 8d 45 fc 8d 95 7b ff ff ff b9 81 00 00 00 e8 ?? ?? fa ff 8d 95 74 ff ff ff 8b 45 fc e8 ?? ?? fa ff 8b 85 74 ff ff ff ba ?? ?? 45 00 e8 ?? ?? fa ff 84 c0 74 0b a1 ?? ?? 45 00 c7 00 01 00 00 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Nish_B_2147648070_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Nish.B"
        threat_id = "2147648070"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Nish"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "TIEAdvBHOFactory" ascii //weight: 1
        $x_1_2 = {54 49 45 4d 6f 6e 69 74 6f 72 [0-16] 68 74 74 70 3a 2f 2f}  //weight: 1, accuracy: Low
        $x_2_3 = {8b 4a f8 41 7e ?? f0 ff 42 f8 87 10 85 d2 74 ?? 8b 4a f8 49 7c ?? f0 ff 4a f8 75 ?? 8d 42 f8 e8}  //weight: 2, accuracy: Low
        $x_2_4 = {8b 45 08 66 c7 00 ff ff 8b c3 8b 15 ?? ?? ?? ?? e8 ?? ?? ?? ?? 8b 45 0c 50 8b 45 10 50 8b 45 14 50 57 53 8d 45 f8 8b d6}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


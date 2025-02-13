rule Trojan_Win32_Skintrim_A_2147600597_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Skintrim.gen!A"
        threat_id = "2147600597"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Skintrim"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {eb 5c 8d 8c 24 28 01 00 00 68 ?? ?? ?? ?? 51 ff d7 8b f0 83 c4 08 85 f6 0f 84 ee 00 00 00 b9 41 00 00 00 33 c0 8d 7c 24 20 8d 54 24 20 f3 ab 68 04 01 00 00 52 aa ff 15 ?? ?? ?? ?? 68 ?? ?? ?? ?? ff 15}  //weight: 1, accuracy: Low
        $x_1_2 = {e9 cc 01 00 00 8d 8c 24 2c 01 00 00 68 ?? ?? ?? ?? 51 ff d6 83 c4 08 89 44 24 10 85 c0 74 3e b9 41 00 00 00 33 c0 8d 7c 24 24 8d 54 24 24 f3 ab 68 04 01 00 00 52 aa ff 15 ?? ?? ?? ?? 68 ?? ?? ?? ?? ff 15}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win32_Skintrim_B_2147609864_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Skintrim.gen!B"
        threat_id = "2147609864"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Skintrim"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "21"
        strings_accuracy = "Low"
    strings:
        $n_8_1 = {72 73 72 63 00}  //weight: -8, accuracy: High
        $x_10_2 = {e0 00 0f 01 0b 01 06 00}  //weight: 10, accuracy: High
        $x_10_3 = {4d 5a 90 00 03 00 00 00 04 00 00 00 ff ff 00 00 b8}  //weight: 10, accuracy: High
        $x_1_4 = {8b c7 2b cf be ?? ?? ?? 00 8a 14 01 88 10 40 4e 75 f7 89}  //weight: 1, accuracy: Low
        $x_1_5 = {4f 75 f7 89 0f 00 8b ?? 2b ?? bf ?? ?? ?? ?? 8a 14 ?? 88}  //weight: 1, accuracy: Low
        $x_1_6 = {4a 75 f7 89 0f 00 8b ?? 2b ?? (ba|be|bf) ?? ?? ?? ?? 8a ?? ?? 88}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (not (any of ($n*))) and
        (
            ((2 of ($x_10_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_Skintrim_E_2147622438_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Skintrim.E"
        threat_id = "2147622438"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Skintrim"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = "FAVORIT NETWORK" ascii //weight: 2
        $x_2_2 = "Spain and with corporate address at Rambla Catalunya , 12" ascii //weight: 2
        $x_2_3 = {53 00 45 00 4c 00 45 00 43 00 54 00 20 00 2a 00 20 00 46 00 52 00 4f 00 4d 00 20 00 41 00 6e 00 74 00 69 00 56 00 69 00 72 00 75 00 73 00 50 00 72 00 6f 00 64 00 75 00 63 00 74 00 [0-6] 5c 00 5c 00 2e 00 5c 00 72 00 6f 00 6f 00 74 00 5c 00 53 00 65 00 63 00 75 00 72 00 69 00 74 00 79 00 43 00 65 00 6e 00 74 00 65 00 72 00}  //weight: 2, accuracy: Low
        $x_1_4 = "The Software includes an ad-supported engine or component" ascii //weight: 1
        $x_1_5 = "Do you want to send this software to a friend" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((3 of ($x_2_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_Skintrim_F_2147622496_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Skintrim.F"
        threat_id = "2147622496"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Skintrim"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {6d 79 6d 75 74 73 67 6c 77 6f 72 6b 00}  //weight: 2, accuracy: High
        $x_2_2 = {70 6c 61 74 65 66 6f 72 6d 3d 00}  //weight: 2, accuracy: High
        $x_1_3 = "87494a0ba8f8f94efd7debcaf91847e4691a6cfc2e9e4ed8eb5a4a79f729b9e63bfcddfa2d9ceb1a2a985739f54afb7dedcefd1c4be60a8808" ascii //weight: 1
        $x_2_4 = {3c 5f 45 47 4d 43 5f 3e 00 00 00 00 5f 00 53 00 59 00 53 00 54 00 45 00 4d 00 5f 00 44 00 49 00 52 00 5f 00 5c 00 00 00 5f 53 59 53 54 45 4d 5f 44 49 52 5f 5c 00 00 00 3c 2f 43 46 47 3e 00 00}  //weight: 2, accuracy: High
        $x_1_5 = {c6 00 6e 8b 06 59 c6 40 01 6f 8b 06 c6 40 02 5f 8b 06 c6 40 03 61 8b 06 c6 40 04 6e 8b 06 c6 40 05 74 8b 06 c6 40 06 69 8b 06 c6 40 07 76 8b 06 c6 40 08 69 8b 06 c6 40 09 72}  //weight: 1, accuracy: High
        $x_2_6 = {74 02 89 08 8b 45 10 3b c3 74 05 8b 55 e8 89 10 81 f9 c8 00 00 00 0f ?? ?? 02 00 00 bf 0a 02 00 00}  //weight: 2, accuracy: Low
        $x_3_7 = {7c 6f 53 8a 06 84 c0 74 5d 3c 2a 74 59 46 80 3e 00 74 53 8a 0e 50 88 4d 08 46}  //weight: 3, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((3 of ($x_2_*) and 1 of ($x_1_*))) or
            ((4 of ($x_2_*))) or
            ((1 of ($x_3_*) and 1 of ($x_2_*) and 2 of ($x_1_*))) or
            ((1 of ($x_3_*) and 2 of ($x_2_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_Skintrim_H_2147626203_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Skintrim.H"
        threat_id = "2147626203"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Skintrim"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {ff ff ff 53 c6 85 ?? ff ff ff 74 c6 85 ?? ff ff ff 61 c6 85 ?? ff ff ff 72 c6 85 ?? ff ff ff 74 c6 85 ?? ff ff ff 4d c6 85 ?? ff ff ff 43}  //weight: 1, accuracy: Low
        $x_1_2 = {ff ff 31 c6 85 ?? ?? ff ff 36 c6 85 ?? ?? ff ff 36 c6 85 ?? ?? ff ff 39 c6 85 ?? ?? ff ff 37 c6 85 ?? ?? ff ff 35 c6 85 ?? ?? ff ff 32 c6 85 ?? ?? ff ff 37 c6 85 ?? ?? ff ff 30 c6 85 ?? ?? ff ff 32 c6 85 ?? ?? ff ff 39 c6 85 ?? ?? ff ff 30 c6 85 ?? ?? ff ff 33 c6 85 ?? ?? ff ff 34}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}


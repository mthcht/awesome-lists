rule Trojan_Win64_AppleChris_YBE_2147965496_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/AppleChris.YBE!MTB"
        threat_id = "2147965496"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "AppleChris"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {83 7c 24 34 0a 7d 23 e8 00 d1 00 00 99 b9 5f 00 00 00 f7 f9 8b c2 83 c0 20 48 63 4c 24 34 48 8d 15 77 7f 0c 00 88 04 0a}  //weight: 1, accuracy: High
        $x_1_2 = {48 33 c4 48 89 84 24 ?? ?? ?? ?? b8 44 00 00 00 66 89 84 24 ?? ?? ?? ?? b8 68 00 00 00 66 89 84 24 ?? ?? ?? ?? b8 53 00 00 00 66 89 84 24 a4 00 00 00 b8 2d}  //weight: 1, accuracy: Low
        $x_1_3 = {b8 67 00 00 00 66 89 84 24 ?? ?? ?? ?? b8 4d 00 00 00 66 89 84 24 ?? ?? ?? ?? b8 7a 00 00 00 66 89 84 24}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_AppleChris_YBF_2147965497_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/AppleChris.YBF!MTB"
        threat_id = "2147965497"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "AppleChris"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {48 8d 4c 24 20 48 8d 05 24 fd ff ff 48 89 44 24 28 33 c0 48 89 44 24 30 48 89 44 24 38 ff 15 8d cf 15 00 b9 d0 07 00 00 ff 15 02 d1 15 00 eb f3}  //weight: 1, accuracy: Low
        $x_1_2 = {58 00 46 00 45 00 58 00 59 00 43 00 44 00 41 00 50 00 50 00 4c 00 45 00 30 00 35 00 43 00 48 00 52 00 49 00 53}  //weight: 1, accuracy: High
        $x_1_3 = {3c 24 75 10 48 8b 54 24 40 48 8d 4d 51 e8 ed e1 ff ff eb 78 3c 25 75 10 48 8b 54 24 40 48 8d 4d 51 e8 89 ed ff ff eb 64 3c 2a}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (2 of ($x*))
}


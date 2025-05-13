rule Trojan_Win64_AsyncRat_RPX_2147902277_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/AsyncRat.RPX!MTB"
        threat_id = "2147902277"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "AsyncRat"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {41 b9 40 00 00 00 31 c9 41 b8 00 10 00 00 ba d3 ca 00 00 ff 10 b9 d0 07 00 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_AsyncRat_RPY_2147902278_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/AsyncRat.RPY!MTB"
        threat_id = "2147902278"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "AsyncRat"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {8b c2 c1 c9 08 41 03 c8 8b d3 41 33 c9 c1 ca 08 41 03 d1 41 c1 c0 03 41 33 d2 41 c1 c1 03 44 33 ca 44 33 c1 41 ff c2 41 8b db 44 8b d8 41 83 fa 1b 72 cd}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_AsyncRat_CCHU_2147903527_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/AsyncRat.CCHU!MTB"
        threat_id = "2147903527"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "AsyncRat"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {4c 8d 8c 24 60 02 00 00 4c 8d 84 24 30 02 00 00 48 8d 15 ?? ?? 01 00 48 8d 0d ?? ?? 01 00 ff 15}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_AsyncRat_ASC_2147922422_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/AsyncRat.ASC!MTB"
        threat_id = "2147922422"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "AsyncRat"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_5_1 = {48 98 48 8b 95 a8 04 00 00 48 01 d0 0f b6 00 32 85 a7 04 00 00 48 8b 8d 90 04 00 00 8b 95 bc 04 00 00 48 63 d2 88 04 11 83 85 bc 04 00 00 01 8b 95 bc 04 00 00 8b 85 5c 04 00 00 39 c2}  //weight: 5, accuracy: High
        $x_3_2 = {4d 89 c1 49 89 c8 48 89 c1 48 8b 05 5a 6b 00 00 ff d0 48 8b 85 78 04 00 00 48 8d 50 30 48 8b 85 70 04 00 00 48 8b 80 88 00 00 00 48 83 c0 10 48 89 c1 48 8b 85 40 04 00 00 48 c7 44 24 20 00 00 00 00 41 b9 08 00 00 00 49 89 d0 48 89 ca 48 89 c1}  //weight: 3, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_AsyncRat_ASC_2147922422_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/AsyncRat.ASC!MTB"
        threat_id = "2147922422"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "AsyncRat"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {48 83 ec 28 48 8d 15 f5 44 00 00 48 8d 0d f6 78 00 00 e8 ?? ?? ?? ?? 48 8d 0d 32 34 00 00 48 83 c4 28}  //weight: 5, accuracy: Low
        $x_2_2 = "seftali\\x64\\Release\\seftali.pdb" ascii //weight: 2
        $x_3_3 = "https://github.com/errias/XWorm-Rat-Remote-Administration-Tool-/raw/main/XWormUI.exe" wide //weight: 3
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_AsyncRat_ASY_2147926329_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/AsyncRat.ASY!MTB"
        threat_id = "2147926329"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "AsyncRat"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {33 d2 41 8b c5 f7 74 24 24 48 8b 45 a8 44 0f be 0c 02 45 33 c8 48 8b 4f 10 48 8b 57 18 48 3b ca}  //weight: 2, accuracy: High
        $x_1_2 = "loader\\x64\\Release\\Espio.pdb" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_AsyncRat_BSA_2147926523_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/AsyncRat.BSA!MTB"
        threat_id = "2147926523"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "AsyncRat"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_10_1 = {55 48 83 ec 20 48 8d 6c 24 20 48 8b 09 0f b6 d2 e8 af 68 06 00 83 f8 ff 74 08 31 c0 48 83 c4 20 5d}  //weight: 10, accuracy: High
        $x_10_2 = {31 d2 e8 bf 5c 06 00 48 8b 36 e8 8b 51 06 00 48 89 f1 89 c2 49 89 f8 e8 6e 4d 06 00 83 f8 ff 0f 84 98}  //weight: 10, accuracy: High
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win64_AsyncRat_BT_2147936628_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/AsyncRat.BT!MTB"
        threat_id = "2147936628"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "AsyncRat"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_4_1 = {4c 01 c2 48 81 c2 ?? 00 00 00 44 33 12 41 01 c2 48 81 c1 01 00 00 00 48 81 f9 ?? ?? 00 00 44 89 d0 44 89 55 ?? 48 89 4d ?? 89 45 ?? 75}  //weight: 4, accuracy: Low
        $x_1_2 = {4d 01 c1 49 81 c1 ?? 00 00 00 45 8b 11}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_AsyncRat_BU_2147937165_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/AsyncRat.BU!MTB"
        threat_id = "2147937165"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "AsyncRat"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_3_1 = {48 c1 e1 08 48 01 ca 48 81 c2 ?? 00 00 00 44 8b 12 45 33 11 41 01 c2 49 81 f8 ?? ?? 00 00 44 89 d0 44 89 55 ?? 4c 89 45 ?? 89 45 cc 75}  //weight: 3, accuracy: Low
        $x_2_2 = {48 8b 45 e0 c7 05 ?? ?? ?? ?? ?? ?? 00 00 48 8b 4d f8 8a 14 01 4c 8b 45 e8 41 88 14 00 48 05 01 00 00 00 4c 8b 4d f0 4c 39 c8 48 89 45 e0 75}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_AsyncRat_CCJX_2147941161_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/AsyncRat.CCJX!MTB"
        threat_id = "2147941161"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "AsyncRat"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_5_1 = {33 d2 48 8b c7 49 f7 f6 49 8d 0c 39 41 0f b6 04 0a 42 32 04 02 88 01 48 ff c7 49 3b fd 72}  //weight: 5, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


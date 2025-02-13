rule Trojan_Win64_Bazarldr_ZZ_2147767144_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Bazarldr.ZZ"
        threat_id = "2147767144"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Bazarldr"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {48 83 ec 78 83 60 08 00 48 8b e9 b9 4c 77 26 07 44 8b fa 33 db e8 a4 04 00 00 b9 49 f7 02 78 4c 8b e8 e8 97 04 00 00 b9 58 a4 53 e5}  //weight: 1, accuracy: High
        $x_1_2 = {48 89 44 24 20 e8 88 04 00 00 b9 10 e1 8a c3 48 8b f0 e8 7b 04 00 00 b9 af b1 5c 94}  //weight: 1, accuracy: High
        $x_1_3 = {48 89 44 24 30 e8 6c 04 00 00 b9 33 00 9e 95 48 89 44 24 28 4c 8b e0 e8 5a 04 00 00 48 63 7d 3c}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Bazarldr_ZZ_2147772812_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Bazarldr.ZZ!MTB"
        threat_id = "2147772812"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Bazarldr"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "C:\\Windows\\explorer.exe" ascii //weight: 1
        $x_1_2 = "Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer" ascii //weight: 1
        $x_1_3 = "Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\Network" ascii //weight: 1
        $x_1_4 = {4c 8b c7 48 8b d8 33 c0 48 85 db 48 8b cb 0f 45 d0 89 15 [0-4] 48 8b d6 e8 [0-4] 48 8b 74 24 38 48 8b c3 48 8b 5c 24 30 48 83 c4 ?? 5f c3}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Bazarldr_ZY_2147773506_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Bazarldr.ZY"
        threat_id = "2147773506"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Bazarldr"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {45 8b 01 b8 ff ff ff ff 4d 03 c3 41 0f b6 08 85 c9 0f 84 a2 00 00 00 66 0f 1f 84 00 00 00 00 00 33 c1 4d 8d 40 01 8b d0 8b c8 c1 e1 1d c1 f9 1f 81 e1 19 c4 6d 07}  //weight: 1, accuracy: High
        $x_1_2 = {c1 e2 1f c1 fa 1f 81 e2 96 30 07 77 33 d1 8b c8 c1 e1 19 c1 f9 1f 81 e1 90 41 dc 76 33 d1 8b c8 c1 e1 1a c1 f9 1f 81 e1 c8 20 6e 3b 33 d1 8b c8 c1 e1 1b c1 f9 1f}  //weight: 1, accuracy: High
        $x_1_3 = {81 e1 64 10 b7 1d 33 d1 8b c8 c1 e1 1c c1 f9 1f 81 e1 32 88 db 0e 33 d1 8b c8 c1 e9 08 33 d1 8b c8 c1 e1 18 c1 f9 1f 81 e1 20 83 b8 ed c1 e0 1e 33 d1 c1 f8 1f 8b c8 8b c2}  //weight: 1, accuracy: High
        $x_1_4 = {81 e1 2c 61 0e ee 33 c1 41 0f b6 08 85 c9 0f 85 67 ff ff ff f7 d0 3b c7 74 27 41 ff c2 49 83 c1 04 44 3b d3 0f 82 31 ff ff ff}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Bazarldr_MR_2147777415_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Bazarldr.MR!MTB"
        threat_id = "2147777415"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Bazarldr"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "12"
        strings_accuracy = "Low"
    strings:
        $x_6_1 = {48 89 5c 24 20 ff 15 [0-4] 85 c0 [0-6] ff d3 48 8d [0-3] c7 45 [0-5] c7 45 [0-5] ff 15 [0-4] 4d 85 [0-3] 75}  //weight: 6, accuracy: Low
        $x_3_2 = {00 6b 65 72 6e 65 6c 33 32 2e 64 6c 6c 00 00 00 00 46 69 6e 64 52 65 73 6f 75 72 63 65 41 00 00 00 53 69 7a 65 6f 66 52 65 73 6f 75 72 63 65}  //weight: 3, accuracy: High
        $x_1_3 = {4c 8b 02 8b 4a 08 4c 89 00 89 48 08 c3}  //weight: 1, accuracy: High
        $x_1_4 = {8b 02 48 8b 4a 04 41 89 02 49 89 4a 04 49 8b c3 c3}  //weight: 1, accuracy: High
        $x_1_5 = {4c 8b 02 8b 4a 08 44 0f b6 4a 0c 4c 89 00 89 48 08 44 88 48 0c c3}  //weight: 1, accuracy: High
        $x_1_6 = {48 0f b6 02 8b 4a 01 48 8b 52 05 41 88 02 41 89 4a 01 49 89 52 05 49 8b c3 c3}  //weight: 1, accuracy: High
        $x_1_7 = {4c 8b 02 8b 4a 08 44 0f b7 4a 0c 4c 89 00 89 48 08 66 44 89 48 0c c3}  //weight: 1, accuracy: High
        $x_1_8 = {48 0f b7 02 8b 4a 02 48 8b 52 06 66 41 89 02 41 89 4a 02 49 89 52 06 49 8b c3 c3}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_6_*) and 6 of ($x_1_*))) or
            ((1 of ($x_6_*) and 1 of ($x_3_*) and 3 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win64_Bazarldr_ZV_2147787740_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Bazarldr.ZV"
        threat_id = "2147787740"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Bazarldr"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "51"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {f1 d5 00 fa 4c 62 cc f4 0f 0b}  //weight: 1, accuracy: High
        $x_10_2 = {41 b9 12 01 00 00}  //weight: 10, accuracy: High
        $x_10_3 = {41 b8 1b 01 00 00}  //weight: 10, accuracy: High
        $x_10_4 = {41 b9 92 04 00 00}  //weight: 10, accuracy: High
        $x_10_5 = {41 b8 9b 04 00 00}  //weight: 10, accuracy: High
        $x_10_6 = {00 00 00 00 01 00 00 80 00 00 00 80 00 00 00 01 00 01}  //weight: 10, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


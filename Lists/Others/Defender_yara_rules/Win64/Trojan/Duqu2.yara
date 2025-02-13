rule Trojan_Win64_Duqu2_H_2147696118_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Duqu2.H!!Duqu2.gen!A"
        threat_id = "2147696118"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Duqu2"
        severity = "Critical"
        info = "Duqu2: an internal category used to refer to some threats"
        info = "gen: malware that is detected using a generic signature"
        info = "A: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_ARHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {74 1e 8b 45 67 48 03 c7 48 3b d8 74 13 e8 a9 33 00 00 33 d2 41 b8 00 80 00 00 48 8b cb ff 50 58}  //weight: 1, accuracy: High
        $x_1_2 = {81 38 63 42 38 72 75 07 b8 01 00 00 00 eb 3d}  //weight: 1, accuracy: High
        $x_1_3 = {c7 03 63 42 38 72 48 89 83 30 01 00 00 b8 01 00 00 00 eb 02}  //weight: 1, accuracy: High
        $x_1_4 = {41 c7 00 5c 00 42 00 41 c7 40 04 61 00 73 00 41 c7 40 08 65 00 4e 00 41 c7 40 0c 61 00 6d 00 41 c7 40 10 65 00 64 00 41 c7 40 14 4f 00 62 00 41 c7 40 18 6a 00 65 00 41 c7 40 1c 63 00 74 00 41 c7 40 20 73 00 5c 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

rule Trojan_Win64_Duqu2_H_2147696118_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Duqu2.H!!Duqu2.gen!A"
        threat_id = "2147696118"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Duqu2"
        severity = "Critical"
        info = "Duqu2: an internal category used to refer to some threats"
        info = "gen: malware that is detected using a generic signature"
        info = "A: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_ARHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {74 09 48 83 c0 02 66 39 28 75 f7 c7 00 5c 00 4e 00 c7 40 04 54 00 44 00 b9 4c 00 4c 00}  //weight: 1, accuracy: High
        $x_1_2 = {66 c7 03 48 b8 4c 89 73 02 4c 8d 4c 24 40 44 8d 47 70 8b d7 48 8b ce 66 c7 43 0a ff e0 ff 55 28}  //weight: 1, accuracy: High
        $x_1_3 = {74 22 80 3e 4c 75 0b 48 8d 4e 03 80 39 b8 48 0f 44 f1 2b de c6 06 e9 b8 01 00 00 00 83 eb 05 89 5e 01 eb 02}  //weight: 1, accuracy: High
        $x_1_4 = {0f b7 01 b9 ab 4f 5e cd 33 c1 3d e6 15 5e cd 0f 85 8d 00 00 00}  //weight: 1, accuracy: High
        $x_1_5 = {43 8b 94 01 88 00 00 00 33 c1 49 03 d0 3d fb 0a 5e cd}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

rule Trojan_Win64_Duqu2_H_2147696118_2
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Duqu2.H!!Duqu2.gen!A"
        threat_id = "2147696118"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Duqu2"
        severity = "Critical"
        info = "Duqu2: an internal category used to refer to some threats"
        info = "gen: malware that is detected using a generic signature"
        info = "A: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_ARHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {74 14 81 7d 28 74 74 74 74 74 22 41 03 fe 81 ff 04 01 00 00 72 b9}  //weight: 2, accuracy: High
        $x_1_2 = {66 83 7b 02 6b 74 0c 48 83 c3 02 0f b7 03 66 85 c0 75 e7 66 83 3b 30}  //weight: 1, accuracy: High
        $x_1_3 = {0f b7 01 48 8b f9 b9 73 4f 00 63 33 c1 41 8b e9 3d 3e 15 00 63}  //weight: 1, accuracy: High
        $x_1_4 = "\\\\.\\pipe\\{AAFFC4F0-E04B-4C7C-B40A-B45DE971E81E}" ascii //weight: 1
        $x_1_5 = "\\\\.\\pipe\\{AB6172ED-8105-4996-9D2A-597B5F827501}" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((3 of ($x_1_*))) or
            ((1 of ($x_2_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}


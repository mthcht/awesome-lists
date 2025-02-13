rule Trojan_Win64_SunSpot_A_2147772528_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/SunSpot.A!dha"
        threat_id = "2147772528"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "SunSpot"
        severity = "Critical"
        info = "dha: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {fc f3 2a 83 e5 f6 d0 24 ?? bf ce 88 30 c2 48 e7}  //weight: 1, accuracy: Low
        $x_1_2 = {81 8c 85 49 b9 00 06 78 0b e9 ?? 60 26 64 b2 da}  //weight: 1, accuracy: Low
        $n_10_3 = {57 6f 72 6c 64 20 6f ?? 20 57 61 72 63 72 61 66 74}  //weight: -10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (not (any of ($n*))) and
        (all of ($x*))
}

rule Trojan_Win64_SunSpot_B_2147772529_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/SunSpot.B!dha"
        threat_id = "2147772529"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "SunSpot"
        severity = "Critical"
        info = "dha: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {7b 31 32 64 36 31 61 34 31 2d 34 62 37 34 2d 37 ?? 31 30 2d 61 34 64 38 2d 33 30 32 38 64 32 66 35 36 33 39 35 7d}  //weight: 1, accuracy: Low
        $x_1_2 = {7b 35 36 33 33 31 65 34 64 2d 37 36 61 33 2d 30 33 39 30 2d 61 37 ?? 65 2d 35 36 37 61 64 66 35 38 33 36 62 37 7d}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win64_SunSpot_C_2147772530_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/SunSpot.C!dha"
        threat_id = "2147772530"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "SunSpot"
        severity = "Critical"
        info = "dha: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {5b 45 52 52 4f 52 5d 20 2a 2a 2a 53 74 65 70 [0-2] 28 27 25 6c 73 27 2c 27 25 6c 73 27 29 20 66 61 69 6c 73 20 77 69 74 68 20 65 72 72 6f 72 20 25 23 78 2a 2a 2a}  //weight: 1, accuracy: Low
        $x_1_2 = {5b 45 52 52 4f 52 5d 20 53 74 65 70 [0-2] 20 66 61 69 6c 73}  //weight: 1, accuracy: Low
        $x_1_3 = {5b 45 52 52 4f 52 5d 20 53 74 65 70 [0-2] 28 27 25 6c 73 27 29 20 66 61 69 6c 73}  //weight: 1, accuracy: Low
        $x_1_4 = {5b 45 52 52 4f 52 5d 20 53 74 65 70 [0-2] 28 27 25 6c 73 27 2c 27 25 6c 73 27 29 20 66 61 69 6c 73 20 77 69 74 68 20 65 72 72 6f 72 20 25 23 78}  //weight: 1, accuracy: Low
        $x_1_5 = {5b 45 52 52 4f 52 5d 20 53 74 65 70 [0-2] 20 66 61 69 6c 73 20 77 69 74 68 20 65 72 72 6f 72 20 25 23 78}  //weight: 1, accuracy: Low
        $x_1_6 = {5b 25 64 5d 20 53 74 65 70 [0-2] 20 66 61 69 6c 73 20 77 69 74 68 20 65 72 72 6f 72 20 25 23 78}  //weight: 1, accuracy: Low
        $x_1_7 = {5b 45 52 52 4f 52 5d 20 53 74 65 70 [0-2] 28 25 64 2c 25 73 2c 25 64 29 20 66 61 69 6c 73}  //weight: 1, accuracy: Low
        $x_1_8 = {5b 25 64 5d 20 53 6f 6c 75 74 69 6f 6e 20 64 69 72 ?? 63 74 6f 72 79 3a 20 25 6c 73}  //weight: 1, accuracy: Low
        $x_1_9 = {5b 25 64 5d 20 25 30 34 64 2d 25 30 32 64 2d 25 30 32 64 20 25 30 32 ?? 3a 25 30 32 64 3a 25 30 32 64 3a 25 30 33 64 20 25 6c 73}  //weight: 1, accuracy: Low
        $x_1_10 = {5b 25 64 5d 20 2b 20 27 25 73 ?? 20}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (4 of ($x*))
}


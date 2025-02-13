rule Trojan_Win32_Zerobot_A_2147837585_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Zerobot.A!dha"
        threat_id = "2147837585"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Zerobot"
        severity = "Critical"
        info = "dha: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {2f 72 6f 6f 74 2f 62 6f 74 6e 65 74 2f 63 6c 69 65 6e 74 2f [0-32] 2e 67 6f}  //weight: 1, accuracy: Low
        $x_1_2 = {6e 65 77 5f 62 6f 74 6e 65 74 2f 73 ?? 6c 66 52 65 70 6f}  //weight: 1, accuracy: Low
        $x_1_3 = {6e 65 77 5f 62 6f 74 6e 65 74 2f 72 61 ?? 53 6f 63 6b 65 74}  //weight: 1, accuracy: Low
        $x_1_4 = {6d 61 69 6e 2e 41 74 74 ?? 63 6b 54 79 70 65}  //weight: 1, accuracy: Low
        $x_1_5 = {6d 61 69 6e 2e 41 74 74 ?? 63 6b 4f 70 74 69 6f 6e}  //weight: 1, accuracy: Low
        $x_1_6 = {6d 61 69 6e 2e 69 6e 69 ?? 41 6e 74 69 4b 69 6c 6c}  //weight: 1, accuracy: Low
        $x_1_7 = {6d 61 69 6e 2e 52 75 6e 57 69 ?? 68 41 6e 74 69 43 72 61 73 68}  //weight: 1, accuracy: Low
        $x_1_8 = {6d 61 69 6e 2e 41 6e 74 69 43 72 ?? 73 68 45 6e 61 62 6c 65 64}  //weight: 1, accuracy: Low
        $x_1_9 = {6d 61 69 6e 2e 4c 69 6e 75 78 53 74 ?? 72 74 75 70 4d 65 74 68 6f 64 33}  //weight: 1, accuracy: Low
        $x_1_10 = {65 71 2e 6d 61 69 6e 2e 42 6f 74 49 6e 66 ?? 72 6d 61 74 69 6f 6e}  //weight: 1, accuracy: Low
        $x_1_11 = {6b 69 6c 6c 61 6c 6c 20 69 20 2e 69 20 6d 6f 7a 69 2e 6d 20 4d 6f 7a 69 2e 6d 20 6d 6f 7a 69 2e 61 20 4d 6f 7a ?? 2e 61 20 6b 61 69 74 65 6e 20 4e 62 72 75 74 65 20 6d 69 6e 65 72 64}  //weight: 1, accuracy: Low
        $x_1_12 = {63 68 6d 6f 64 20 37 35 35 20 7a 65 72 6f 2e 25 73 3b 20 2e 2f 7a ?? 72 6f 2e 25 73 47 45 54 20 25 73 20 48 54 54 50 2f 25 73}  //weight: 1, accuracy: Low
        $x_1_13 = {43 6f 6e 6e 65 63 74 65 64 ?? 74 6f 20 43 26 43}  //weight: 1, accuracy: Low
        $x_1_14 = {32 38 37 2f 37 36 2f 32 34 38 2f 36 3b 32 35 31 32 35 ?? 36 30 34 36 34 34 37 37 35 33 39 30 36 32 35}  //weight: 1, accuracy: Low
        $x_1_15 = {42 6f 74 20 41 75 74 68 65 ?? 74 69 63 61 74 65 64 21}  //weight: 1, accuracy: Low
        $x_1_16 = {42 6f 74 20 69 6e 66 ?? 72 6d 61 74 69 6f 6e 20 73 65 6e 74 21}  //weight: 1, accuracy: Low
        $x_1_17 = {73 65 6c 66 52 65 70 6f 2e 54 65 6c 6e ?? 74 43 72 61 63 6b 65 72}  //weight: 1, accuracy: Low
        $x_1_18 = {5a 65 72 6f 53 74 72 65 73 ?? 65 72 20 42 6f 74 6e 65 74}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (2 of ($x*))
}


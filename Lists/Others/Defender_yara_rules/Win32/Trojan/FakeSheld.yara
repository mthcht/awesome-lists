rule Trojan_Win32_FakeSheld_131471_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/FakeSheld"
        threat_id = "131471"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "FakeSheld"
        severity = "High"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {2f 64 69 73 63 6f 75 6e 74 5f 70 75 72 63 68 61 73 65 2e 68 74 6d 00}  //weight: 1, accuracy: High
        $x_1_2 = {2f 70 75 72 63 68 61 73 65 2e 68 74 6d 00}  //weight: 1, accuracy: High
        $x_1_3 = {49 6d 6d 65 64 69 61 74 65 20 72 65 6d 6f 76 61 6c 20 6e 65 65 64 65 64 00}  //weight: 1, accuracy: High
        $x_1_4 = {57 69 6e 20 44 65 73 6b 74 6f 70 20 41 64 77 61 72 65 20 69 73 20 61 20 67 65 6e 65 72 69 63 20 44 65 73 6b 74 6f 70 20 48 69 6a 61 63 6b 65 72 20 61 6e 64 20 54 72 6f 6a 61 6e 20 44 6f 77 6e 6c 6f 61 64 65 72 20 74 68 61 74 20 64 69 73 70 6c 61 79 73 20 64 65 73 6b 74 6f 70 20 61 64 73 2e 00}  //weight: 1, accuracy: High
        $x_1_5 = {43 6f 6d 70 6c 65 78 65 6c 20 54 72 6f 6a 61 6e [0-4] 47 65 6e 65 72 69 63 20 74 72 6f 6a 61 6e 20 61 6e 64 20 61 64 77 61 72 65 20 69 6e 73 74 61 6c 6c 65 72 20 74 68 61 74 20 72 75 6e 73 20 76 61 72 69 6f 75 73 20 33 72 64 20 70 61 72 74 79 20 61 64 77 61 72 65 2e 00}  //weight: 1, accuracy: Low
        $x_1_6 = {53 63 61 6e 20 26 26 20 43 6c 65 61 6e 00}  //weight: 1, accuracy: High
        $x_1_7 = {44 65 66 69 6e 69 74 69 6f 6e 73 20 63 6f 75 6e 74 3a 20 25 64 20 53 69 67 6e 61 74 75 72 65 73 20 63 6f 75 6e 74 3a 20 25 64 00}  //weight: 1, accuracy: High
        $x_1_8 = {59 6f 75 72 20 73 79 73 74 65 6d 20 69 73 20 69 6e 66 65 63 74 65 64 21 20 53 63 61 6e 20 66 6f 75 6e 64 20 25 64 20 74 68 72 65 61 74 73 2e 20 52 75 6e 20 74 68 72 65 61 74 20 72 65 6d 6f 76 61 6c 20 6e 6f 77 3f 00}  //weight: 1, accuracy: High
        $x_1_9 = {25 64 20 75 70 64 61 74 65 64 20 73 69 67 6e 61 74 75 72 65 73 20 64 6f 77 6e 6c 6f 61 64 65 64 2e 00}  //weight: 1, accuracy: High
        $x_1_10 = {25 64 20 75 70 64 61 74 65 64 20 64 65 66 69 6e 69 74 69 6f 6e 73 20 64 6f 77 6e 6c 6f 61 64 65 64 2e 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (6 of ($x*))
}


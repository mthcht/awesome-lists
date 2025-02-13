rule TrojanSpy_Win32_Hanove_B_2147681673_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:Win32/Hanove.B"
        threat_id = "2147681673"
        type = "TrojanSpy"
        platform = "Win32: Windows 32-bit platform"
        family = "Hanove"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {80 38 00 74 08 fe 08 40 80 38 00 75 f8 c3}  //weight: 1, accuracy: High
        $x_1_2 = {00 48 6f 73 74 3a 20 00 [0-64] 2f 71 69 71 00}  //weight: 1, accuracy: Low
        $x_1_3 = {3f 63 64 61 74 61 3d 00 26 64 65 74 61 69 6c 3d 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanSpy_Win32_Hanove_C_2147681677_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:Win32/Hanove.C"
        threat_id = "2147681677"
        type = "TrojanSpy"
        platform = "Win32: Windows 32-bit platform"
        family = "Hanove"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "llehS.tpircSW" wide //weight: 1
        $x_1_2 = "Set Y = jObj.CreateShortcut(Replace(X & " wide //weight: 1
        $x_1_3 = "Chr(82) & Chr(69) & Chr(71) & Chr(32) & Chr(97) & Chr(100) & Chr(100) & Chr(32) & Chr(72) & Chr(75) & Chr(67) & Chr(85)" wide //weight: 1
        $x_1_4 = {00 00 53 00 68 00 65 00 6c 00 6c 00 20 00 73 00 74 00 61 00 72 00 74 00 65 00 64 00 20 00 61 00 74 00 3a 00 20 00 00 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

rule TrojanSpy_Win32_Hanove_D_2147681678_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:Win32/Hanove.D"
        threat_id = "2147681678"
        type = "TrojanSpy"
        platform = "Win32: Windows 32-bit platform"
        family = "Hanove"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {00 00 20 00 6b 00 20 00 20 00 61 00 20 00 20 00 20 00 20 00 73 00 20 00 70 00 20 00 20 00 20 00 20 00 65 00 72 00 20 00 00 00}  //weight: 1, accuracy: High
        $x_1_2 = {00 00 7c 00 4e 00 20 00 6f 00 20 00 72 00 20 00 74 00 20 00 6f 00 20 00 6e 00 00 00}  //weight: 1, accuracy: High
        $x_1_3 = "llehS.tpircSW" wide //weight: 1
        $x_1_4 = "osF ,Z ,K ,L ,Y ,X ,jbOj miD" wide //weight: 1
        $x_2_5 = {47 00 6f 00 6f 00 67 00 6c 00 53 00 65 00 72 00 76 00 69 00 63 00 73 00 00 00 [0-32] 00 52 00 2e 00 76 00 62 00 73 00 00 00}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 3 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule TrojanSpy_Win32_Hanove_A_2147681680_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:Win32/Hanove.gen!A"
        threat_id = "2147681680"
        type = "TrojanSpy"
        platform = "Win32: Windows 32-bit platform"
        family = "Hanove"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "   M    S   X    M     L   2    .    X M     L   H   T    T   P " wide //weight: 1
        $x_1_2 = "   W     i   n H     t   t   p   .   W   i   n    H   t t p  R   e    q   u   e    s    t   " wide //weight: 1
        $x_1_3 = {57 00 20 00 53 00 20 00 63 00 20 00 72 00 20 00 69 00 20 00 70 00 20 00 74 00 2e 00 20 00 53 00 20 00 68 00 65 00 20 00 6c 00 6c 00 00 00}  //weight: 1, accuracy: High
        $x_1_4 = {53 00 20 00 74 00 20 00 61 00 72 00 74 00 20 00 75 00 20 00 70 00 00 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

rule TrojanSpy_Win32_Hanove_E_2147681699_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:Win32/Hanove.E"
        threat_id = "2147681699"
        type = "TrojanSpy"
        platform = "Win32: Windows 32-bit platform"
        family = "Hanove"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {53 4f 46 54 57 41 52 45 5c 4d 69 63 72 6f 73 6f 66 74 5c 57 69 6e 64 6f 77 73 5c 43 75 72 72 65 6e 74 56 65 72 73 69 6f 6e 5c 52 75 6e [0-16] 00 55 70 6c 6f 61 64 65 72 00}  //weight: 2, accuracy: Low
        $x_2_2 = {5f 53 5a 53 4f 46 54 5f 4d 55 54 45 58 00}  //weight: 2, accuracy: High
        $x_2_3 = {00 6a 75 70 74 65 72 74 6d 70 2e 74 6d 70 00}  //weight: 2, accuracy: High
        $x_2_4 = {2f 75 70 6c 6f 2e 70 68 70 00 30 00 00 68 74 74 70 3a 2f 2f}  //weight: 2, accuracy: Low
        $x_1_5 = {2e 64 6f 63 00 00 00 00 2e 64 6f 63 78 00 00 00 2e 78 6c 73 00 00 00 00 2e 78 6c 73 78 00 00 00 2e 70 64 66}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((3 of ($x_2_*) and 1 of ($x_1_*))) or
            ((4 of ($x_2_*))) or
            (all of ($x*))
        )
}

rule TrojanSpy_Win32_Hanove_B_2147681700_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:Win32/Hanove.gen!B"
        threat_id = "2147681700"
        type = "TrojanSpy"
        platform = "Win32: Windows 32-bit platform"
        family = "Hanove"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {5c 48 61 6e 67 4f 76 65 72 [0-48] 2e 70 64 62 00}  //weight: 2, accuracy: Low
        $x_2_2 = {00 45 4d 53 46 52 54 43 42 56 44 00}  //weight: 2, accuracy: High
        $x_1_3 = {fe 08 40 80 38 00 75 f8}  //weight: 1, accuracy: High
        $x_2_4 = {48 3d f2 01 00 00 77 17 8a 14 01 80 fa 2f 74 0f 80 fa 5c 74 0a c6 44 01 01 2f c6 44 01 02 00}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_2_*) and 1 of ($x_1_*))) or
            ((3 of ($x_2_*))) or
            (all of ($x*))
        )
}


rule TrojanSpy_Win32_Fucobha_A_2147648514_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:Win32/Fucobha.A"
        threat_id = "2147648514"
        type = "TrojanSpy"
        platform = "Win32: Windows 32-bit platform"
        family = "Fucobha"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {25 73 5c 77 64 6d 61 75 64 2e 64 72 76 00}  //weight: 1, accuracy: High
        $x_1_2 = {00 6d 79 66 75 63 00}  //weight: 1, accuracy: High
        $x_1_3 = "%s/tmpxor.dat" ascii //weight: 1
        $x_1_4 = "%s?filepath=%s&filename=%s" ascii //weight: 1
        $x_1_5 = "System Version: %d.%d %s (Build %d)" ascii //weight: 1
        $x_1_6 = "%s/order.dat" ascii //weight: 1
        $x_2_7 = {8a 1c 0a 32 5c 35 ?? 46 3b f0 88 19 75 02 33 f6 41 4f 75 ec}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((6 of ($x_1_*))) or
            ((1 of ($x_2_*) and 4 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule TrojanSpy_Win32_Fucobha_A_2147648514_1
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:Win32/Fucobha.A"
        threat_id = "2147648514"
        type = "TrojanSpy"
        platform = "Win32: Windows 32-bit platform"
        family = "Fucobha"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "30"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {00 00 25 73 2f 74 6d 70 2e 64 61 74 00 00}  //weight: 10, accuracy: High
        $x_10_2 = {00 00 48 6f 73 74 4e 61 6d 65 3a 20 25 73 0d 0a 49 50 3a 20 25 73 0d 0a 50 72 6f 78 79 3a 20 25 73 0d 0a 55 73 65 72 3a 20 25 73 0d 0a 53 79 73 74 65 6d 44 69 72 3a 20 25 73 0d 0a 4f 53 20 4c 61 6e 67 75 61 67 65 20 56 65 72 73 69 6f 6e 3a 20 25 64 0d 0a 73 79 73 74 65 6d 20 76 65 72 73 69 6f 6e 3a 20 25 64 2e 25 64 20 25 73 20 28 62 75 69 6c 64 20 25 64 29 0d 0a}  //weight: 10, accuracy: High
        $x_1_3 = "%s?filepath=%s&filename=%s" ascii //weight: 1
        $x_1_4 = "/c taskkill /f /im hwp.exe" ascii //weight: 1
        $x_10_5 = {8a 4f 01 83 c7 01 3a cb 75 f6 8b c8 c1 e9 02 f3 a5 8b c8 83 e1 03 f3 a4 8d [0-4] 00 00}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((3 of ($x_10_*))) or
            (all of ($x*))
        )
}


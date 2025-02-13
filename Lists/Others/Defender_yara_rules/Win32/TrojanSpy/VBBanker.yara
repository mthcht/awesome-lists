rule TrojanSpy_Win32_VBBanker_A_2147688982_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:Win32/VBBanker.A"
        threat_id = "2147688982"
        type = "TrojanSpy"
        platform = "Win32: Windows 32-bit platform"
        family = "VBBanker"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "153"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {00 00 73 00 65 00 6e 00 64 00 70 00 61 00 73 00 73 00 77 00 6f 00 72 00 64 00 00 00}  //weight: 1, accuracy: High
        $x_1_2 = {00 00 73 00 65 00 6e 00 64 00 75 00 73 00 65 00 72 00 6e 00 61 00 6d 00 65 00 00 00}  //weight: 1, accuracy: High
        $x_1_3 = {00 00 63 00 3a 00 5c 00 74 00 65 00 73 00 74 00 65 00 2e 00 74 00 78 00 74 00 00 00}  //weight: 1, accuracy: High
        $x_1_4 = {00 45 4d 61 69 6c 43 00}  //weight: 1, accuracy: High
        $x_1_5 = {00 44 61 64 6f 73 00}  //weight: 1, accuracy: High
        $x_50_6 = {00 00 30 00 30 00 31 00 36 00 30 00 34 00 36 00 30 00 37 00 31 00 30 00 38 00 36 00 37 00 37 00 35 00 36 00 32 00 30 00 34 00 00 00}  //weight: 50, accuracy: High
        $x_50_7 = {00 00 30 00 30 00 31 00 36 00 36 00 32 00 37 00 37 00 30 00 44 00 30 00 46 00 36 00 33 00 37 00 38 00 30 00 35 00 30 00 30 00 00 00}  //weight: 50, accuracy: High
        $x_50_8 = {00 00 30 00 30 00 31 00 36 00 30 00 34 00 30 00 37 00 30 00 33 00 30 00 45 00 36 00 36 00 37 00 33 00 37 00 44 00 36 00 33 00 00 00}  //weight: 50, accuracy: High
        $x_50_9 = {35 00 37 00 35 00 44 00 35 00 31 00 35 00 39 00 35 00 43 00 31 00 45 00 35 00 33 00 35 00 46 00 35 00 44 00 00 00}  //weight: 50, accuracy: High
        $x_50_10 = {8b 10 6a 01 51 56 52 c7 45 d4 01 00 00 00 c7 45 cc 02 00 00 00 ff 15 ?? ?? ?? ?? 8b d0 8d 4d e0 ff d3 50 ff 15 ?? ?? ?? ?? 0f bf 4d e4 0f bf c0 33 c1 50 ff 15}  //weight: 50, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((3 of ($x_50_*) and 3 of ($x_1_*))) or
            ((4 of ($x_50_*))) or
            (all of ($x*))
        )
}


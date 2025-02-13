rule TrojanSpy_Win32_Bimagip_A_2147689359_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:Win32/Bimagip.A"
        threat_id = "2147689359"
        type = "TrojanSpy"
        platform = "Win32: Windows 32-bit platform"
        family = "Bimagip"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {63 6f 6c 6f 73 6f 73 2e 62 61 74 00}  //weight: 1, accuracy: High
        $x_1_2 = {42 4d 47 41 50 50 00}  //weight: 1, accuracy: High
        $x_1_3 = {41 53 6b 79 6c 69 6e 65 2e 65 78 65 00}  //weight: 1, accuracy: High
        $x_1_4 = {4f 70 74 69 6f 6e 73 2e 64 61 74 ?? ?? ?? ?? ?? ?? ?? ?? ?? 2e 61 73 7a 00}  //weight: 1, accuracy: Low
        $x_1_5 = {63 3a 5c 69 6e 73 69 64 65 74 6d ?? ?? ?? ?? ?? ?? ?? ?? ?? 43 3a 5c 61 6e 61 6c 79 73 69 73 00}  //weight: 1, accuracy: Low
        $x_1_6 = {6a 6f 65 62 6f 78 63 6f 6e 74 72 6f 6c 2e 65 78 65 00}  //weight: 1, accuracy: High
        $x_1_7 = {64 69 72 5f 77 61 74 63 68 2e 64 6c 6c ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 75 73 65 72 6e 61 6d 65 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


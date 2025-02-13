rule TrojanSpy_Win32_Figpuf_A_2147626150_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:Win32/Figpuf.A"
        threat_id = "2147626150"
        type = "TrojanSpy"
        platform = "Win32: Windows 32-bit platform"
        family = "Figpuf"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {c1 e8 08 33 04 95}  //weight: 1, accuracy: High
        $x_1_2 = {6a 0d ff 15 ?? ?? ?? ?? 89 47 28 3b c6 75 22}  //weight: 1, accuracy: Low
        $x_1_3 = {83 f9 22 0f 87 ?? ?? 00 00 74 7c 8b c1 83 e8 08 74 6c 48 74 60}  //weight: 1, accuracy: Low
        $x_1_4 = {8a 00 85 c9 75 04 8b ca eb 02 03 ce 32 01 88 45 e8}  //weight: 1, accuracy: High
        $x_1_5 = {68 00 28 00 00 8d 85 24 d7 ff ff 50 56 ff 15 ?? ?? ?? ?? 85 c0 7f e8}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}


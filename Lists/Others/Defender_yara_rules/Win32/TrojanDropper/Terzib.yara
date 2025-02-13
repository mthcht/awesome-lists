rule TrojanDropper_Win32_Terzib_A_2147638687_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:Win32/Terzib.A"
        threat_id = "2147638687"
        type = "TrojanDropper"
        platform = "Win32: Windows 32-bit platform"
        family = "Terzib"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {33 c0 b1 85 8a ?? ?? ?? 40 00 32 d1 88 ?? ?? ?? 40 00 40 3d 80 54 01 00 72 ea 56 68 80 54 01 00 6a 01 68 ?? ?? 40 00 e8 ?? 00 00 00}  //weight: 1, accuracy: Low
        $x_1_2 = {00 77 62 00 00 25 73 5c 73 6d 63 67 75 69 2e 65 78 65 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


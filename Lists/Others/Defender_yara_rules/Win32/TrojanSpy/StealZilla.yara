rule TrojanSpy_Win32_StealZilla_A_2147685204_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:Win32/StealZilla.A"
        threat_id = "2147685204"
        type = "TrojanSpy"
        platform = "Win32: Windows 32-bit platform"
        family = "StealZilla"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {2f 69 6e 64 65 78 2e 70 68 70 3f 72 65 63 6f 72 64 3d 00 3a 00 40 00 25 64 00 47 45 54 20 00 20 48 54 54 50 2f 31 2e 31 0d 0a 00 [0-3] 55 73 65 72 2d 41 67 65 6e 74 3a 20 4f 70 65 72 61 2f 39 2e 38 30 20 28 57 69 6e 64 6f 77 73 20 4e 54 20 36 2e 31 3b 20 55 3b 20 72 75 29 20 50 72 65 73 74 6f 2f}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


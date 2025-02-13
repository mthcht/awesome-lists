rule Virus_Win32_Kadia_A_2147600921_0
{
    meta:
        author = "defender2yara"
        detection_name = "Virus:Win32/Kadia.A"
        threat_id = "2147600921"
        type = "Virus"
        platform = "Win32: Windows 32-bit platform"
        family = "Kadia"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {e8 00 00 00 00 5e 8b c6 2d 13 20 00 00 66 81 38 30 30 0f 85 c0 00 00 00 66 c7 00 42 53 8b ce 81 e9 ?? ?? ?? ?? 8b 09 81 e1 ff ff 00 00 02 cd}  //weight: 1, accuracy: Low
        $x_1_2 = {55 8b ec 81 c4 d4 fe ff ff 6a 00 6a 02 ff 53 28 89 85 d4 fe ff ff 68 28 01 00 00 8f 85 d8 fe ff ff 8d 85 d8 fe ff ff 50 ff b5 d4 fe ff}  //weight: 1, accuracy: High
        $x_1_3 = {b5 6b 0c 61 24 34 1e 1f 1f 8a e0 8a e2 1f b3 c8 69 65 34 1e 1f 1f 88 c8 e1 e0 e0 6f 65 38 1e 1f 1f 6d 65 38 1e 1f 1f b0 1f 55 34 1e 1f}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}


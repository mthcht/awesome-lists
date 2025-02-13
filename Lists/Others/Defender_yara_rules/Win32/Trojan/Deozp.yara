rule Trojan_Win32_Deozp_A_2147681352_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Deozp.A"
        threat_id = "2147681352"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Deozp"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {00 76 65 72 73 69 6f 6e 3d 25 75 26 69 64 3d 25 75 00}  //weight: 1, accuracy: High
        $x_1_2 = {0f b7 06 c1 ea 06 69 d2 ?? ?? ?? ?? 03 ca 0f b7 56 02 03 c1 89 4d 08 0f b7 4e 06 8b d9 c1 e3 10 33 d9 83 fb 01 77 ?? 8b d9 c1 e3 18}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


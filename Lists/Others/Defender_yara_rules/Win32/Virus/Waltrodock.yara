rule Virus_Win32_Waltrodock_A_2147656182_0
{
    meta:
        author = "defender2yara"
        detection_name = "Virus:Win32/Waltrodock.A"
        threat_id = "2147656182"
        type = "Virus"
        platform = "Win32: Windows 32-bit platform"
        family = "Waltrodock"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {9c e8 01 00 00 00 ?? 83 c4 04 60 e8 14 00 00 00 ?? ?? ?? ?? ?? ff d1 61 9d ff 15 ?? ?? ?? ?? e9 ?? ?? ?? ?? 58 e8 e6 ff ff ff 62 64 63 61 70 45 78 33 32 2e 64 6c 6c}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


rule Worm_Win32_Chir_D_2147600725_0
{
    meta:
        author = "defender2yara"
        detection_name = "Worm:Win32/Chir.D"
        threat_id = "2147600725"
        type = "Worm"
        platform = "Win32: Windows 32-bit platform"
        family = "Chir"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "msftdm.exe" wide //weight: 1
        $x_1_2 = {83 66 14 00 33 c0 c7 46 18 07 00 00 00 66 89 46 04 8b 44 24 08 8d 48 02 66 8b 10 40 40 66 85 d2 75 f6}  //weight: 1, accuracy: High
        $x_1_3 = {76 14 80 7d ?? 00 74 08 8a 4d ?? 02 c8 30 0c 18 40 3b 45 ?? 72 ec}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (2 of ($x*))
}


rule Trojan_Win32_Duzse_A_2147633320_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Duzse.A"
        threat_id = "2147633320"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Duzse"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "*VIRTUAL*" wide //weight: 1
        $x_1_2 = "*VBOX*" wide //weight: 1
        $x_2_3 = {8b 45 e4 03 85 ?? ff ff ff 0f 80 7c 01 00 00 89 45 e4 8b 45 e4 3b 85 ?? ff ff ff 0f 8f ad 00 00 00 8b 45 e8 89 85 ?? ff ff ff c7 85 ?? ff ff ff 08 00 00 00 c7 45 d8 01 00 00 00 c7 45 d0 02 00 00 00}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


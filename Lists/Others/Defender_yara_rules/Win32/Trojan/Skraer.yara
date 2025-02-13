rule Trojan_Win32_Skraer_A_2147682918_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Skraer.A"
        threat_id = "2147682918"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Skraer"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8a 07 89 55 ?? 84 c0 74 ?? 3c 66 75 ?? 8b c7 33 c9 8a 14 02 8a 18 3a da 75 01}  //weight: 1, accuracy: Low
        $x_1_2 = {8b 75 08 57 8d 86 ?? ?? 00 00 50 8b 46 04 c7 45 ?? 00 00 00 00 ff d0}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


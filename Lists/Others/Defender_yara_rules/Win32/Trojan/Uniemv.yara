rule Trojan_Win32_Uniemv_A_2147685711_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Uniemv.A"
        threat_id = "2147685711"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Uniemv"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "11"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {2e 70 68 70 3f 75 73 65 72 3d 25 73 26 69 64 3d [0-8] 26 74 79 70 65 3d ?? 26 68 61 73 68 72 61 74 65 3d 25 73}  //weight: 10, accuracy: Low
        $x_1_2 = {85 c0 75 11 68 60 ea 00 00 ff 15 ?? ?? ?? ?? 46 83 fe 05 7c e6 05 00 e8}  //weight: 1, accuracy: Low
        $x_1_3 = {ff d3 85 c0 7e 17 8a 45 ?? 88 84 35 ?? ?? ?? ?? 3c 0a 74 09 46 81 fe ff 1f 00 00 7c}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_10_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}


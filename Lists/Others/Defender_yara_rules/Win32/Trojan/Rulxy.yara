rule Trojan_Win32_Rulxy_A_2147679856_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Rulxy.A"
        threat_id = "2147679856"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Rulxy"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {3d 2e 69 63 6f 0f 84 ?? ?? 00 00 3d 2e 63 6c 72 0f 84 ?? ?? 00 00 3d 2e 78 6d 6c 0f 84 ?? ?? 00 00 25 ff ff ff 00 3d 2e 6a 73 00 0f 84 ?? ?? 00 00}  //weight: 1, accuracy: Low
        $x_1_2 = {3d 47 45 54 20 74 ?? 3d 50 4f 53 54 75 ?? 80 7f 04 20 74}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


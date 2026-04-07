rule Trojan_Win32_Badtile_K_2147966473_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Badtile.K!AMTB"
        threat_id = "2147966473"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Badtile"
        severity = "Critical"
        info = "AMTB: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_6_1 = {8b 4c 24 18 8b 74 24 08 8b 7c c1 0c 8b 54 c1 08 31 c9 89 7c 24 0c 33 7c 24 30 89 54 24 70 31 f2 09 fa 8b 54 24 30 0f 95 c1 3b 74 24 70 1b 54 24 0c ba ff 00 00 00 0f 42 ca 40 83 c3 f8 80 f9 01 74 ba}  //weight: 6, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


rule Trojan_Win32_Udochka_BH_2147820248_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Udochka.BH!MTB"
        threat_id = "2147820248"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Udochka"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {8b 45 0c 8b d3 03 c6 3b c7 7c 03 8b 55 08 33 c9 85 d2 7e 0c 8a 44 0d f0 30 04 0e 41 3b ca 7c f4 29 5d 08 03 f3 ff 4d fc 75 d6}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


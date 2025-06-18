rule Trojan_Win32_Alevaul_DC_2147943961_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Alevaul.DC!MTB"
        threat_id = "2147943961"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Alevaul"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "15"
        strings_accuracy = "High"
    strings:
        $x_10_1 = {0f b6 c2 03 c8 81 e1 ff 00 00 00 89 4d fc 8a 44 0e 08 88 44 3e 08 88 54 0e 08 0f b6 4c 3e 08 0f b6 c2 03 c8 81 e1 ff 00 00 80}  //weight: 10, accuracy: High
        $x_5_2 = {8a 44 31 08 8b 4d 08 32 04 0b 88 01 41 ff 4d 0c 89 4d 08 8b 4d fc}  //weight: 5, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


rule Trojan_Win32_Sekur_RPY_2147908631_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Sekur.RPY!MTB"
        threat_id = "2147908631"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Sekur"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {89 43 28 83 7b 30 00 8b 4d 0c 8b 45 08 74 57 8b 7b 38 2b 7b 34 89 7c 24 04 c7 44 24 0c 40 00 00 00 c7 44 24 08 00 30 00 00 c7 04 24 00 00 00 00 ff 53 14 83 ec 10 89 c6 8b 43 34 89 7c 24 08 89 44 24 04 89 34 24}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


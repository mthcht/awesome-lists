rule Trojan_Win32_Ketrican_MA_2147849573_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Ketrican.MA!MTB"
        threat_id = "2147849573"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Ketrican"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_5_1 = {8b c6 8b 4d e8 8a 14 08 88 54 1d f8 43 41 89 5d ec 89 4d e8 83 fb 04 75 6d 33 f6 8a 44 35 f8 6a 01 8d 4d fc 51 88 45 fc}  //weight: 5, accuracy: High
        $x_1_2 = "localhost&client_secret=" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


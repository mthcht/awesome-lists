rule Trojan_Win32_Crusis_RPZ_2147851573_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Crusis.RPZ!MTB"
        threat_id = "2147851573"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Crusis"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b 45 f4 83 c0 01 89 45 f4 8b 4d fc 8b 55 fc 8b 44 8d b8 2b 44 95 b4 2b 05 ?? ?? ?? ?? 39 45 f4 73 27 8b 4d fc 8b 55 f4 03 54 8d b4 03 15 ?? ?? ?? ?? 8b 45 fc 8b 4d dc 8b 04 81 8b 4d f4 8b 75 ec 8a 14 16 88 14 08 eb b7}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


rule Trojan_Win32_WarZone_RDA_2147893096_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/WarZone.RDA!MTB"
        threat_id = "2147893096"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "WarZone"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {8b c1 99 f7 ff 8a 44 15 98 30 04 31 41}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_WarZone_A_2147935984_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/WarZone.A!MTB"
        threat_id = "2147935984"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "WarZone"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {83 3d fc 65 49 00 00 ?? ?? a1 fc 65 49 00 50 ?? ?? ?? ?? ?? 33 c0 a3 fc 65 49 00 33 c0 a3 0c 66 49 00 29 c0 a3 00 66 49 00 c7 05 08 66 49 00 ff ff ff ff c6 05 f0 1e 49 00 00 c3}  //weight: 2, accuracy: Low
        $x_2_2 = {8b 10 09 d2 74 38 8b 4a f8 49 74 32 53 50 5b 8b 42 fc ?? ?? ?? ?? ?? 50 5a 8b 03 89 13 50 8b 48 fc ?? ?? ?? ?? ?? 58 8b 48 f8 49}  //weight: 2, accuracy: Low
        $x_1_3 = "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


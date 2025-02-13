rule Trojan_Win32_Heodo_RPG_2147812420_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Heodo.RPG!MTB"
        threat_id = "2147812420"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Heodo"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {33 d2 03 c1 b9 69 09 00 00 f7 f1 8b 4d f4 2b 55 d0 03 55 cc 03 15 ?? ?? ?? ?? 0f b6 04 1a 8b 55 f0 30 04 0a 41 89 4d f4 3b cf b9 69 09 00 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Heodo_RPH_2147812421_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Heodo.RPH!MTB"
        threat_id = "2147812421"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Heodo"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {0f be c0 83 c4 08 66 0f 6e c8 f3 0f e6 c9 0f 28 c1 f2 0f 5c 45 98 f2 0f 11 45 98 f2 0f 59 c1 f2 0f 2c d8 80 fb 5b 74 c5}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Heodo_ED_2147833841_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Heodo.ED!MTB"
        threat_id = "2147833841"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Heodo"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_5_1 = {83 c3 03 0f af 5d 10 03 f8 83 c0 04 0f af f8 8b 85 8c fd ff ff 03 de 2b c1 03 85 8c fd ff ff 8a d3 32 95 a3 fd ff ff}  //weight: 5, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


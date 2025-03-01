rule Trojan_Win64_SystemBc_YAA_2147889457_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/SystemBc.YAA!MTB"
        threat_id = "2147889457"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "SystemBc"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {89 c2 81 c2 20 00 00 00 41 89 c0 45 89 c1 25 1f 00 00 00 89 c0 41 89 c2 46 8a 1c 11 48 8b 8d ?? ?? ?? ?? 42 8a 1c 09 44 28 db 42 88 1c 09 8b 45 94 39 c2 89 95}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_SystemBc_YAB_2147892726_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/SystemBc.YAB!MTB"
        threat_id = "2147892726"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "SystemBc"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {8b 5d cc 03 5d ac 81 eb 67 2b 00 00 03 5d e8 2b d8 6a 00 e8 ?? ?? ?? ?? 2b d8 8b 45 d8 31 18 6a 00 e8 ?? ?? ?? ?? ba 04 00 00 00 2b d0}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


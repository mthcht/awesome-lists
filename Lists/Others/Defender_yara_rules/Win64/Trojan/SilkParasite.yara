rule Trojan_Win64_SilkParasite_GV_2147977582_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/SilkParasite.GV!MTB"
        threat_id = "2147977582"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "SilkParasite"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {41 0f b6 d1 48 31 c2 49 0f af d0 41 0f b7 c1 48 c1 e8 08 48 31 d0 49 0f af c0 44 0f b7 09 48 83 c1 02 66 45 85 c9 75 d8}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_SilkParasite_GC_2147977596_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/SilkParasite.GC!MTB"
        threat_id = "2147977596"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "SilkParasite"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {8b 8d ec fd ff ff 03 c2 0f b6 c0 0f b6 84 05 fc fe ff ff 30 04 0b 43 81 fb e3 54 02 00 72 96}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


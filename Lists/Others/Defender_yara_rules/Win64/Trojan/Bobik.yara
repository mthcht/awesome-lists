rule Trojan_Win64_Bobik_CZP_2147840683_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Bobik.CZP!MTB"
        threat_id = "2147840683"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Bobik"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {44 8b d0 eb ?? ?? c1 e2 04 eb ?? ?? ?? 41 c1 ea 05 eb ?? ?? ?? 41 33 d2 71 ?? 69 07 ?? ?? ?? ?? 01 2c 45 8b d4 eb 02 03 70 41 8b cc eb ?? ?? ?? c1 e9 0b eb ?? ?? ?? ?? 83 e1}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


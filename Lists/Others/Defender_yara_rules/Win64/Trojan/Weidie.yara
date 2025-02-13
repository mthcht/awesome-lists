rule Trojan_Win64_Weidie_A_2147898682_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Weidie.A!MTB"
        threat_id = "2147898682"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Weidie"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {4c 0f b6 11 44 8b 1d ?? ?? ?? ?? 41 81 e3 ?? ?? ?? ?? 45 33 d3 45 8b d2 47 33 04 91 44 89 05}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


rule Trojan_Win64_Luca_GZT_2147923494_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Luca.GZT!MTB"
        threat_id = "2147923494"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Luca"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {48 8b 08 48 ba ?? ?? ?? ?? ?? ?? ?? ?? 48 31 d1 8a 40 08 34 ?? 48 89 8c 24 ?? ?? ?? ?? 88 84 24}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


rule Trojan_Win64_HuntingSnakes_PA_2147957036_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/HuntingSnakes.PA!MTB"
        threat_id = "2147957036"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "HuntingSnakes"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "eicar_fud.com" ascii //weight: 1
        $x_2_2 = {8b 45 fc 48 98 0f b6 84 05 ?? ?? ?? ?? 89 c2 8b 45 f4 31 d0 89 c2 8b 45 fc 48 98 88 94 05 ?? ?? ?? ?? 83 45 fc 01 8b 45 fc 3b 45 f8 7c}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


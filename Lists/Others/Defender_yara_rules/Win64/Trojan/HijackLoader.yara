rule Trojan_Win64_HijackLoader_GPA_2147957225_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/HijackLoader.GPA!MTB"
        threat_id = "2147957225"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "HijackLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_4_1 = {74 3e 48 8b 84 24 ?? ?? 00 00 8a 08 48 8b 84 24 ?? ?? 00 00 88 08 48 8b 84 24 ?? ?? 00 00 48 83 c0 01 48 89 84 24 ?? ?? 00 00 48 8b 84 24 ?? ?? 00 00 48 83 c0 01 48 89 84 24 ?? ?? 00 00 eb a5}  //weight: 4, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


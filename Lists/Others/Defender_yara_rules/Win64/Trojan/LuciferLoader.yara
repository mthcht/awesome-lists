rule Trojan_Win64_LuciferLoader_A_2147909842_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/LuciferLoader.A!MTB"
        threat_id = "2147909842"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "LuciferLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {48 89 9c 24 ?? ?? ?? ?? 41 0f b7 5e ?? 48 89 bc 24 ?? ?? ?? ?? 48 83 c3 ?? 41 8b fd 66 41 39 7e}  //weight: 2, accuracy: Low
        $x_2_2 = {30 14 08 48 ff c0}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


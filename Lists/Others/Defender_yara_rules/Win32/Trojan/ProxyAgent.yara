rule Trojan_Win32_ProxyAgent_GKM_2147756313_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/ProxyAgent.GKM!MTB"
        threat_id = "2147756313"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "ProxyAgent"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {83 e9 03 89 0d ?? ?? ?? ?? 8b 15 ?? ?? ?? ?? 2b 15 ?? ?? ?? ?? 89 15 ?? ?? ?? ?? a1 ?? ?? ?? ?? 03 05 ?? ?? ?? ?? a3 ?? ?? ?? ?? b9 87 8a 00 00 85 c9 0f 85}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


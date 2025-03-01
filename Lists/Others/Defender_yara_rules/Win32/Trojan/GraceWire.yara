rule Trojan_Win32_Gracewire_MB_2147762866_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Gracewire.MB!MTB"
        threat_id = "2147762866"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Gracewire"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b 45 bc 83 c0 ?? 89 45 bc 83 7d bc ?? 7d 23 c7 45 b8 ?? ?? ?? ?? c7 45 f8 ?? ?? ?? ?? 8b 4d b8 81 e1 ?? ?? 00 00 03 4d f8 0f af 4d f8 89 4d f8 eb ce}  //weight: 1, accuracy: Low
        $x_1_2 = {8b 55 e4 83 c2 ?? 89 55 e4 81 7d e4 ?? ?? 00 00 73 16 8b 85 ?? ?? ?? ?? 03 45 e4 8b 4d e4 8a 91 ?? ?? ?? ?? 88 10 eb d8}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


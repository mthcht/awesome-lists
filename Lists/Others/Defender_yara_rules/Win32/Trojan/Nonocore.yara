rule Trojan_Win32_Nonocore_SX_2147739723_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Nonocore.SX!MTB"
        threat_id = "2147739723"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Nonocore"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {59 f7 f9 0f af 45 ?? 89 45 ?? 0f b6 45 ?? 33 45 ?? 88 45 ?? 8b 45 ?? 03 45 ?? 8b 4d ?? 83 c1 ?? 0f af 4d ?? 03 c1 8b 4d ?? 03 4d ?? c1 e1 ?? 2b c1 03 45 ?? 89 45 ?? 8d 85 ?? ?? ?? ?? 85 c0}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


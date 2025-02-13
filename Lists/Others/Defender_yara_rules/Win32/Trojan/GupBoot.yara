rule Trojan_Win32_GupBoot_A_2147905545_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/GupBoot.A!MTB"
        threat_id = "2147905545"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "GupBoot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {66 85 dd 66 2b d4 66 33 d4 64 8b 10 66 0f ab e0 66 c1 e0 ?? d2 c0 89 54 25 ?? c1 f0 ?? 0f b7 c7 80 dc ?? 8b 07 f5 66 3b c4 8d bf}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


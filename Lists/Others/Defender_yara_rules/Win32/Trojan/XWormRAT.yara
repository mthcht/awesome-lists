rule Trojan_Win32_XWormRAT_A_2147901099_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/XWormRAT.A!MTB"
        threat_id = "2147901099"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "XWormRAT"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {2b 72 14 8b 55 ?? 8b 52 0c 8a 04 08 32 04 32 8b 4d}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


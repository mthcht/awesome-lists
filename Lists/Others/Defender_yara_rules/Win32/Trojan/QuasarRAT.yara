rule Trojan_Win32_QuasarRAT_A_2147893085_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/QuasarRAT.A!MTB"
        threat_id = "2147893085"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "QuasarRAT"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {8b 45 f4 8b 44 85 d0 89 45 ec 8b 45 ec 89 04 24 e8 ?? ?? ?? ?? 89 45 e8 8d 45 cc 89 44 24 08 8b 45 e8 89 44 24 04 8b 45 ec 89 04 24 e8 ?? ?? ?? ?? 89 45 e4 83 7d e4}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


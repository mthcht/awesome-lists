rule Trojan_Win32_ParallaxRAT_A_2147902373_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/ParallaxRAT.A!MTB"
        threat_id = "2147902373"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "ParallaxRAT"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {fe c3 f7 db 81 c3 ?? ?? ?? ?? f7 db f7 db f6 d3 f6 d3 fe c3 33 ff ff cb 29 9d ?? ?? ff ff c0 e3 ?? 66 81 ?? ?? ?? c0 eb ?? f7 db f6 d3 81 f3}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


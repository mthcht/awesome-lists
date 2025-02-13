rule Trojan_Win32_ExpInject_VC_2147756729_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/ExpInject.VC!MTB"
        threat_id = "2147756729"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "ExpInject"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8a 14 30 88 15 ?? ?? ?? ?? 8b 15 ?? ?? ?? ?? 8a 04 30 8a 1c 11 32 d8 88 1c 11 a1 ?? ?? ?? ?? 40 83 f8 ?? a3 ?? ?? ?? ?? 8b 0d ?? ?? ?? ?? c7 05 ?? ?? ?? ?? ?? ?? ?? ?? 41 4f 89 0d ?? ?? ?? ?? 8b 35}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


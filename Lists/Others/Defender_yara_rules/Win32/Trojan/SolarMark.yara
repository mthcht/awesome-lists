rule Trojan_Win32_SolarMark_JLA_2147838725_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/SolarMark.JLA!MTB"
        threat_id = "2147838725"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "SolarMark"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {b1 10 8b 1d ?? ?? 44 00 8b c3 bf 0a 00 00 00 99 f7 ff 80 c2 30 33 c0 8a c1 88 14 06 8b c3 bb 0a 00 00 00 99 f7 fb 8b d8 49 85 db 75 db b1 1c a1 ?? ?? 44 00 8b d0 83 e2 0f 8a 92 ?? ?? 44 00 33 db 8a d9 88 14 1e c1 e8 04 49 85 c0 75 e6}  //weight: 1, accuracy: Low
        $x_1_2 = {00 bb 58 dd 44 00 8a 86 ?? ?? ?? 00 32 03 a2}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


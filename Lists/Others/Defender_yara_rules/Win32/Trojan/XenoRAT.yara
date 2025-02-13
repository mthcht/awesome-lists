rule Trojan_Win32_XenoRAT_A_2147919512_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/XenoRAT.A!MTB"
        threat_id = "2147919512"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "XenoRAT"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {8b 45 e8 83 c0 ?? 89 45 e8 83 7d e8 ?? 7d ?? 8b f4 8d 4d f7 51 6a 00 6a 00 ff ?? ?? ?? ?? ?? 3b f4 e8 ?? ?? ?? ?? 8b 55 ec 83 c2 ?? 89 55 ec}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


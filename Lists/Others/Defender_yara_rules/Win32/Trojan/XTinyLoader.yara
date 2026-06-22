rule Trojan_Win32_XTinyLoader_AXT_2147972064_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/XTinyLoader.AXT!MTB"
        threat_id = "2147972064"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "XTinyLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {60 8b 7d 08 bb 00 00 00 00 b9 00 00 00 00 8b 45 0c 83 f8 00 7e 17 32 0f 32 1f 80 e9 20 80 f9 20 7d f8 d3 c3 47 8a 17 48}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


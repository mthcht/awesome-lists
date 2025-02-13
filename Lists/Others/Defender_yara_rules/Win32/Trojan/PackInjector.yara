rule Trojan_Win32_PackInjector_MB_2147895352_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/PackInjector.MB!MTB"
        threat_id = "2147895352"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "PackInjector"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_5_1 = {8b 45 dc 8b 00 89 45 d0 83 45 dc 04 8b 45 d4 89 45 d8 8b 45 d8 83 e8 04 89 45 d8 33 c0 89 45 ec 33 c0 89 45 b4 33 c0 89 45 b0 8b 45 e0 8b 10 ff 12}  //weight: 5, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


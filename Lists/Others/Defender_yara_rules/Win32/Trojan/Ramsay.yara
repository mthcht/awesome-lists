rule Trojan_Win32_Ramsay_DA_2147894434_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Ramsay.DA!MTB"
        threat_id = "2147894434"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Ramsay"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {33 d2 b9 1a 00 00 00 f7 f1 89 55 f4 0f b7 55 f4 83 c2 61 66 89 55 fc 8b 45 f0 8b 4d f8 66 8b 55 fc 66 89 14 41 6a 0a ff 15}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


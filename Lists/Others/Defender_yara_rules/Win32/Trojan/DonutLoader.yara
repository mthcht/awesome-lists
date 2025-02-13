rule Trojan_Win32_DonutLoader_RPX_2147908314_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/DonutLoader.RPX!MTB"
        threat_id = "2147908314"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "DonutLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {ff d0 89 85 7c 02 00 00 48 8b 85 90 02 00 00 48 8b 80 f0 00 00 00 48 8b 95 58 02 00 00 48 89 d1 ff d0 48 8b 85 90 02 00 00 48 8b 80 f0 00 00 00 48 8b 95 60 02 00 00 48 89 d1 ff d0}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


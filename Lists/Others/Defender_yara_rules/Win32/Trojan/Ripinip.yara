rule Trojan_Win32_Ripinip_PA_2147956327_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Ripinip.PA!MTB"
        threat_id = "2147956327"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Ripinip"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {33 d2 8a 14 39 33 d0 8b 44 24 24 03 c2 41 89 44 24 24 8b 44 24 5c 3b c8 72}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


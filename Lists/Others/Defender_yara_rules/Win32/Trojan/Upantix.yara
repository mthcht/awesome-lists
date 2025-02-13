rule Trojan_Win32_Upantix_DA_2147818858_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Upantix.DA!MTB"
        threat_id = "2147818858"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Upantix"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {ba 00 00 00 20 83 ea 01 75 fb 83 eb 01 75 f1}  //weight: 2, accuracy: High
        $x_2_2 = {8b 45 f8 8b 5d d8 89 d9 29 c1 89 c8 83 c0 01 89 c2 8b 45 c8 39 c2 0f 85}  //weight: 2, accuracy: High
        $x_1_3 = "VirtualAlloc" ascii //weight: 1
        $x_1_4 = "VirtualProtect" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


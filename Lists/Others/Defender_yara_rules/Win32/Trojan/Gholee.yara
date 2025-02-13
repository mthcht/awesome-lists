rule Trojan_Win32_Gholee_BB_2147817957_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Gholee.BB!MTB"
        threat_id = "2147817957"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Gholee"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {8b 55 08 8a 14 8a 32 55 10 88 14 01 41 3b 4d 0c 7c ee}  //weight: 2, accuracy: High
        $x_1_2 = "VirtualProtect" ascii //weight: 1
        $x_1_3 = "VirtualAlloc" ascii //weight: 1
        $x_1_4 = "GetTickCount" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


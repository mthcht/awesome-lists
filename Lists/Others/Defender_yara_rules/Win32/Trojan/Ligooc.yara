rule Trojan_Win32_Ligooc_GM_2147755492_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Ligooc.GM!MTB"
        threat_id = "2147755492"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Ligooc"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b da 8a 54 1c ?? 88 54 3c ?? 88 4c 1c}  //weight: 1, accuracy: Low
        $x_1_2 = {33 c0 8a 44 3c ?? 81 e1 ?? ?? ?? ?? 03 c1 [0-48] 8a 45 ?? 83 c4 ?? 8a 54 14 ?? 32 c2 88 45 ?? 8b 44 24 [0-32] 89 44 24}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Ligooc_DA_2147779722_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Ligooc.DA!MTB"
        threat_id = "2147779722"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Ligooc"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "?PostRtm@@YAHXZ" ascii //weight: 1
        $x_1_2 = "SetTimer" ascii //weight: 1
        $x_1_3 = "KillTimer" ascii //weight: 1
        $x_1_4 = "GetClientRect" ascii //weight: 1
        $x_1_5 = "SendMessageA" ascii //weight: 1
        $x_1_6 = "GetClassNameA" ascii //weight: 1
        $x_1_7 = "GetCurrentThreadId" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


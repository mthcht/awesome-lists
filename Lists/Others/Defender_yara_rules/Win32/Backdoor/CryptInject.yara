rule Backdoor_Win32_CryptInject_2147742899_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/CryptInject!MTB"
        threat_id = "2147742899"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "CryptInject"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "ZwUnmapViewOfSection" ascii //weight: 1
        $x_1_2 = "VirtualAllocEx" ascii //weight: 1
        $x_1_3 = "WXYZabcBACDLMNOPQEFGHIJKRSTUVfghidepqrstjklmnouvwxyz4567890123+/" ascii //weight: 1
        $x_1_4 = "GIlQWWMWWWWaWWWW//2WWLiWWWWWWWWWQWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWiWWWWW8" ascii //weight: 1
        $x_1_5 = "WriteProcessMemory" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_Win32_CryptInject_MBHG_2147851807_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/CryptInject.MBHG!MTB"
        threat_id = "2147851807"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "CryptInject"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {00 ff cc 31 00 14 7c 85 a7}  //weight: 1, accuracy: High
        $x_1_2 = {c4 dd 4e 00 df f8 30 00 00 ff ff ff 08 00 00 00 01 00 00 00 03 00 00 00 e9 00 00 00 4c d6 4e 00 00 d3 4e 00 28 32 40 00 78}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


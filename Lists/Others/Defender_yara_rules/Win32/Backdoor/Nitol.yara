rule Backdoor_Win32_Nitol_2147720659_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Nitol"
        threat_id = "2147720659"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Nitol"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Proxy-agent: BeijiProxy" ascii //weight: 1
        $x_1_2 = "Heartbeat" ascii //weight: 1
        $x_1_3 = "%sias.ini" ascii //weight: 1
        $x_1_4 = "%swuapi.ini" ascii //weight: 1
        $x_1_5 = "%4d-%02d-%02d %02d:%02d:%02d" ascii //weight: 1
        $x_1_6 = "ProxyWaiter|" ascii //weight: 1
        $x_1_7 = "OpenWeb" ascii //weight: 1
        $x_1_8 = "ProxyToBadClose" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_Win32_Nitol_DX_2147819702_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Nitol.DX!MTB"
        threat_id = "2147819702"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Nitol"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {8a 44 1e 01 8a 14 39 46 32 d0 8b c1 88 14 39 99 bd 06 00 00 00 f7 fd 85 d2 75 02 33 f6 8b 44 24 18 41 3b c8 7c da}  //weight: 1, accuracy: High
        $x_1_2 = "VirtualAlloc" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_Win32_Nitol_GIC_2147846148_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Nitol.GIC!MTB"
        threat_id = "2147846148"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Nitol"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "11"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {50 8d 45 dc c7 45 ?? 4b 45 52 4e 50 c7 45 ?? 45 4c 33 32 c7 45 ?? 2e 64 6c 6c c6 45 ?? 00 c7 45 ?? 4c 6f 61 64 c7 45 ?? 4c 69 62 72 c7 45 ?? 61 72 79 41 c6 45 ?? 00 ff 15}  //weight: 10, accuracy: Low
        $x_1_2 = "C:\\Users\\16512\\Desktop\\yk" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


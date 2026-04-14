rule Trojan_Win32_CpidCrptBseDlHj_BB_2147966941_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/CpidCrptBseDlHj.BB"
        threat_id = "2147966941"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "CpidCrptBseDlHj"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "50"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "proxy.dll" ascii //weight: 10
        $x_10_2 = "C:\\Windows\\System32\\CRYPTBASE.dll" ascii //weight: 10
        $x_10_3 = "NtAllocateVirtualMemory" ascii //weight: 10
        $x_10_4 = "NtFreeVirtualMemory" ascii //weight: 10
        $x_10_5 = "SystemFunction041" ascii //weight: 10
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


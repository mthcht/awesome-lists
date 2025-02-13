rule Trojan_Win32_LazInjector_DD_2147743520_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/LazInjector.DD!MSR"
        threat_id = "2147743520"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "LazInjector"
        severity = "Critical"
        info = "MSR: Microsoft Security Response"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "C:\\Intel\\tmp3AC.tmp" ascii //weight: 1
        $x_1_2 = "Injection : WriteProcessMemory Failed" ascii //weight: 1
        $x_1_3 = "Injection : Succeed" ascii //weight: 1
        $x_1_4 = "CreateToolhelp32Snapshot" ascii //weight: 1
        $x_1_5 = "OpenProcess" ascii //weight: 1
        $x_1_6 = "VirtualAllocEx" ascii //weight: 1
        $x_1_7 = "PathFileExistsA" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


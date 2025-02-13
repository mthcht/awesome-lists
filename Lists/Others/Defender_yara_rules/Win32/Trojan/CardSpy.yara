rule Trojan_Win32_CardSpy_DA_2147819992_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/CardSpy.DA!MTB"
        threat_id = "2147819992"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "CardSpy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Agent.pdb" ascii //weight: 1
        $x_1_2 = "CreateToolhelp32Snapshot" ascii //weight: 1
        $x_1_3 = "_MYDEBUG:" ascii //weight: 1
        $x_1_4 = "SetEndOfFile" ascii //weight: 1
        $x_1_5 = "QueryPerformanceCounter" ascii //weight: 1
        $x_1_6 = "GetSystemTimeAsFileTime" ascii //weight: 1
        $x_1_7 = "Bogus JPEG colorspace" ascii //weight: 1
        $x_1_8 = "CreateRemoteThread" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


rule Ransom_Win32_Ziggy_PAA_2147773918_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/Ziggy.PAA!MTB"
        threat_id = "2147773918"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "Ziggy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Ziggy.Properties" ascii //weight: 1
        $x_1_2 = "get_Ziggy_Info" ascii //weight: 1
        $x_1_3 = "Ziggy.Core" ascii //weight: 1
        $x_1_4 = "CreateToolhelp32Snapshot" ascii //weight: 1
        $x_1_5 = "GetCurrentProcessId" ascii //weight: 1
        $x_1_6 = "Debugger Detected" wide //weight: 1
        $x_1_7 = "IsDebuggerPresent" ascii //weight: 1
        $x_1_8 = "COM Surrogate" ascii //weight: 1
        $x_1_9 = "ForceRemove" ascii //weight: 1
        $x_1_10 = "NoRemove" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


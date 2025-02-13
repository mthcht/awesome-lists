rule Backdoor_MSIL_Agentesla_2147755757_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:MSIL/Agentesla!MTB"
        threat_id = "2147755757"
        type = "Backdoor"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Agentesla"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "27"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "FindWindow" ascii //weight: 1
        $x_1_2 = "GetFileAttributes" ascii //weight: 1
        $x_1_3 = "GetModuleHandle" ascii //weight: 1
        $x_1_4 = "GetProcAddress" ascii //weight: 1
        $x_1_5 = "GetUserName" ascii //weight: 1
        $x_1_6 = "CreateProcess" ascii //weight: 1
        $x_1_7 = "GetThreadContext" ascii //weight: 1
        $x_1_8 = "Wow64GetThreadContext" ascii //weight: 1
        $x_1_9 = "SetThreadContext" ascii //weight: 1
        $x_1_10 = "Wow64SetThreadContext" ascii //weight: 1
        $x_1_11 = "ReadProcessMemory" ascii //weight: 1
        $x_1_12 = "WriteProcessMemory" ascii //weight: 1
        $x_1_13 = "NtUnmapViewOfSection" ascii //weight: 1
        $x_1_14 = "irtualAllocEx" ascii //weight: 1
        $x_1_15 = "ResumeThread" ascii //weight: 1
        $x_1_16 = "GetProcesses" ascii //weight: 1
        $x_1_17 = "get_UserName" ascii //weight: 1
        $x_1_18 = "DownloadFile" ascii //weight: 1
        $x_1_19 = "Invoke" ascii //weight: 1
        $x_20_20 = {52 65 5a 65 72 30 56 ?? 2e 65 78 65}  //weight: 20, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_20_*) and 7 of ($x_1_*))) or
            (all of ($x*))
        )
}


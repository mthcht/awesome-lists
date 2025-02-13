rule Trojan_MSIL_DarkInjector_2147777922_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/DarkInjector!MTB"
        threat_id = "2147777922"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "DarkInjector"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "17"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "AntiSB" ascii //weight: 1
        $x_1_2 = "AntiVM" ascii //weight: 1
        $x_1_3 = "CheckDefender" ascii //weight: 1
        $x_1_4 = "RunPS" ascii //weight: 1
        $x_1_5 = "ProcessPersistence" ascii //weight: 1
        $x_1_6 = "CreateProcess" ascii //weight: 1
        $x_1_7 = "GetThreadContext" ascii //weight: 1
        $x_1_8 = "Wow64GetThreadContext" ascii //weight: 1
        $x_1_9 = "SetThreadContext" ascii //weight: 1
        $x_1_10 = "Wow64SetThreadContext" ascii //weight: 1
        $x_1_11 = "ReadProcessMemory" ascii //weight: 1
        $x_1_12 = "WriteProcessMemory" ascii //weight: 1
        $x_1_13 = "NtUnmapViewOfSection" ascii //weight: 1
        $x_1_14 = "VirtualAllocEx" ascii //weight: 1
        $x_1_15 = "ResumeThread" ascii //weight: 1
        $x_1_16 = "StartInject" ascii //weight: 1
        $x_1_17 = "GetInjectionPath" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


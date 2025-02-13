rule Trojan_MSIL_SwotterLoader_2147784173_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/SwotterLoader!MTB"
        threat_id = "2147784173"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "SwotterLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "17"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "AntiSB" ascii //weight: 1
        $x_1_2 = "AntiVM" ascii //weight: 1
        $x_1_3 = "loadresource" ascii //weight: 1
        $x_1_4 = "IsAdministrator" ascii //weight: 1
        $x_1_5 = "ProcessPersistenceWatcher" ascii //weight: 1
        $x_1_6 = "ProtectTheFile" ascii //weight: 1
        $x_1_7 = "StartInject" ascii //weight: 1
        $x_1_8 = "GetInjectionPath" ascii //weight: 1
        $x_1_9 = "DelegateWow64SetThreadContext" ascii //weight: 1
        $x_1_10 = "DelegateSetThreadContext" ascii //weight: 1
        $x_1_11 = "DelegateWow64GetThreadContext" ascii //weight: 1
        $x_1_12 = "DelegateGetThreadContext" ascii //weight: 1
        $x_1_13 = "DelegateVirtualAllocEx" ascii //weight: 1
        $x_1_14 = "DelegateWriteProcessMemory" ascii //weight: 1
        $x_1_15 = "DelegateReadProcessMemory" ascii //weight: 1
        $x_1_16 = "DelegateCreateProcessA" ascii //weight: 1
        $x_1_17 = "DelegateZwUnmapViewOfSection" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


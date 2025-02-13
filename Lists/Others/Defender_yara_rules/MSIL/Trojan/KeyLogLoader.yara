rule Trojan_MSIL_KeyLogLoader_2147761476_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/KeyLogLoader!MTB"
        threat_id = "2147761476"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "KeyLogLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "16"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "CreateProcessA" ascii //weight: 1
        $x_1_2 = "LoadLibraryA" ascii //weight: 1
        $x_1_3 = "IMPORTANT_FILE" ascii //weight: 1
        $x_1_4 = "InjectPE" ascii //weight: 1
        $x_1_5 = "GetProcessById" ascii //weight: 1
        $x_1_6 = "ResumeThread" ascii //weight: 1
        $x_1_7 = "set_FileName" ascii //weight: 1
        $x_1_8 = "set_UseShellExecute" ascii //weight: 1
        $x_1_9 = "RegistryKeyPermissionCheck" ascii //weight: 1
        $x_1_10 = "CreateProjectError" ascii //weight: 1
        $x_1_11 = "Wow64GetThreadContext" ascii //weight: 1
        $x_1_12 = "Wow64SetThreadContext" ascii //weight: 1
        $x_1_13 = "set_CreateNoWindow" ascii //weight: 1
        $x_1_14 = "VirtualAllocEx" ascii //weight: 1
        $x_1_15 = "WriteProcessMemory" ascii //weight: 1
        $x_1_16 = "SkipVerification" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


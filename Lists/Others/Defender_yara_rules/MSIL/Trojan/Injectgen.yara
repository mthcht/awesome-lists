rule Trojan_MSIL_Injectgen_MA_2147807603_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Injectgen.MA!MTB"
        threat_id = "2147807603"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Injectgen"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "11"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {13 05 11 05 20 00 01 00 00 6f ?? ?? ?? 0a 11 05 17 6f ?? ?? ?? 0a 11 05 0b 03 2d 1f 07 06 1f 10 6f ?? ?? ?? 0a 28 ?? ?? ?? 0a 72 ?? ?? ?? 70 6f ?? ?? ?? 0a 6f ?? ?? ?? 0a 2b 1d 07 06 1f 10 6f ?? ?? ?? 0a 28 ?? ?? ?? 0a 72 ?? ?? ?? 70 6f ?? ?? ?? 0a 6f ?? ?? ?? 0a 0c 73 ?? ?? ?? 0a 0d 09 08 17 73 ?? ?? ?? 0a 13 04 11 04 02 16 02 8e 69 6f ?? ?? ?? 0a 11 04 6f ?? ?? ?? 0a de}  //weight: 1, accuracy: Low
        $x_1_2 = "set_KeySize" ascii //weight: 1
        $x_1_3 = "CreateEncryptor" ascii //weight: 1
        $x_1_4 = "CreateDecryptor" ascii //weight: 1
        $x_1_5 = "MemoryStream" ascii //weight: 1
        $x_1_6 = "RijndaelManaged" ascii //weight: 1
        $x_1_7 = "ZipArchive" ascii //weight: 1
        $x_1_8 = "FromBase64String" ascii //weight: 1
        $x_1_9 = "VirtualAllocEx" ascii //weight: 1
        $x_1_10 = "ResumeThread" ascii //weight: 1
        $x_1_11 = "WriteProcessMemory" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Injectgen_MB_2147807606_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Injectgen.MB!MTB"
        threat_id = "2147807606"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Injectgen"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "14"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "ConfusedByAttribute" ascii //weight: 1
        $x_1_2 = "svchost.exe" ascii //weight: 1
        $x_1_3 = "xmr.exe" ascii //weight: 1
        $x_1_4 = "IsLogging" ascii //weight: 1
        $x_1_5 = "CreateDecryptor" ascii //weight: 1
        $x_1_6 = "CreateEncryptor" ascii //weight: 1
        $x_1_7 = "ZipArchive" ascii //weight: 1
        $x_1_8 = "set_KeySize" ascii //weight: 1
        $x_1_9 = "FromBase64" ascii //weight: 1
        $x_1_10 = "MemoryStream" ascii //weight: 1
        $x_1_11 = "SetThreadContext" ascii //weight: 1
        $x_1_12 = "VirtualAllocEx" ascii //weight: 1
        $x_1_13 = "ZwUnmapViewOfSection" ascii //weight: 1
        $x_1_14 = "WriteProcessMemory" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Injectgen_MC_2147810299_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Injectgen.MC!MTB"
        threat_id = "2147810299"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Injectgen"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "9"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {1f 38 16 02 28 ?? ?? ?? 0a 16 9a 6f ?? ?? ?? 0a 28 ?? ?? ?? 06 25 16 03 6f ?? ?? ?? 0a 17 58 20 00 10 00 00 1a 28 ?? ?? ?? 06 0a 25 06 03 28 ?? ?? ?? 0a 03 6f ?? ?? ?? 0a 17 58 16 28 ?? ?? ?? 06 26 25 7e ?? 00 00 0a 16 72 ?? ?? ?? 70 28 ?? ?? ?? 06 72 ?? 00 00 70 28 ?? ?? ?? 06 06 16 16 28 ?? ?? ?? 06 15 28 ?? ?? ?? 06 26 06 16 20 00 80 00 00 28 ?? ?? ?? 06 26 17 2a}  //weight: 1, accuracy: Low
        $x_1_2 = "/CheatSquad Injector" wide //weight: 1
        $x_1_3 = "CreateRemoteThread" ascii //weight: 1
        $x_1_4 = "OpenProcess" ascii //weight: 1
        $x_1_5 = "WriteProcessMemory" ascii //weight: 1
        $x_1_6 = "GifDecoder" ascii //weight: 1
        $x_1_7 = "PROCESS_VM_WRITE" ascii //weight: 1
        $x_1_8 = "AutomaticInjection_Checked" ascii //weight: 1
        $x_1_9 = "DebuggerHiddenAttribute" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


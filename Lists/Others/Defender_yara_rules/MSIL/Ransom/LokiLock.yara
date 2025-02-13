rule Ransom_MSIL_LokiLock_AA_2147852152_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:MSIL/LokiLock.AA!MTB"
        threat_id = "2147852152"
        type = "Ransom"
        platform = "MSIL: .NET intermediate language scripts"
        family = "LokiLock"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "payload" wide //weight: 1
        $x_1_2 = "Loki.Payload.dll" ascii //weight: 1
        $x_1_3 = "SOFTWARE\\Loki" wide //weight: 1
        $x_1_4 = "CreateProcess" ascii //weight: 1
        $x_1_5 = "NtUnmapViewOfSection" ascii //weight: 1
        $x_1_6 = "VirtualAllocEx" ascii //weight: 1
        $x_1_7 = "NtWriteVirtualMemory" ascii //weight: 1
        $x_1_8 = "NtGetContextThread" ascii //weight: 1
        $x_1_9 = "NtSetContextThread" ascii //weight: 1
        $x_1_10 = "NtResumeThread" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


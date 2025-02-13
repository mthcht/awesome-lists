rule Ransom_MSIL_Thanos_DA_2147773494_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:MSIL/Thanos.DA!MTB"
        threat_id = "2147773494"
        type = "Ransom"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Thanos"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "c3RvcCBBbnRpdmlydXM" ascii //weight: 1
        $x_1_2 = "c3RvcCDigJxTb3Bob3MgQ2xlYW4gU2VydmljZeKAnSA" ascii //weight: 1
        $x_1_3 = "RESTORE_FILES_INFO.txt" ascii //weight: 1
        $x_1_4 = "DisableTaskMgr" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_MSIL_Thanos_DB_2147773496_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:MSIL/Thanos.DB!MTB"
        threat_id = "2147773496"
        type = "Ransom"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Thanos"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "WorkerCrypter" ascii //weight: 1
        $x_1_2 = "CheckDefender" ascii //weight: 1
        $x_1_3 = "DisTaskManager" ascii //weight: 1
        $x_1_4 = "LockedFiles" ascii //weight: 1
        $x_1_5 = "EncryptedFiles" ascii //weight: 1
        $x_1_6 = "CheckRemoteDebuggerPresent" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_MSIL_Thanos_PA_2147778242_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:MSIL/Thanos.PA!MTB"
        threat_id = "2147778242"
        type = "Ransom"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Thanos"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "ZGVsZXRlICJIS0NVXFNPRlRXQVJFXE1pY3Jvc29mdFxXaW5kb3dzXEN1cnJlbnRWZXJzaW9uXFJ1biIgL1YgIlJhY2NpbmUgVHJheSIgL0Y=" ascii //weight: 1
        $x_1_2 = "U2V0LU1wUHJlZmVyZW5jZSAtRW5hYmxlQ29udHJvbGxlZEZvbGRlckFjY2VzcyBEaXNhYmxlZA==" ascii //weight: 1
        $x_1_3 = "\\RESTORE_FILES_INFO." ascii //weight: 1
        $x_1_4 = "tor browser" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_MSIL_Thanos_PA_2147778242_1
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:MSIL/Thanos.PA!MTB"
        threat_id = "2147778242"
        type = "Ransom"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Thanos"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "9"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "WorkerCrypter" ascii //weight: 1
        $x_1_2 = "CheckRemoteDebuggerPresent" ascii //weight: 1
        $x_1_3 = "DownloadString" ascii //weight: 1
        $x_1_4 = "FromBase64String" ascii //weight: 1
        $x_1_5 = "SW5mb3JtYXRpb24uLi4=" wide //weight: 1
        $x_1_6 = "USERNAME" wide //weight: 1
        $x_5_7 = "QWxsIHlvdXIgZmlsZXMgd2VyZSBlbmNyeXB0ZWQsIGlmIHlvdSB3YW50IHRvIGdldCB0aGVtIGFsbCBiYWNrLC" wide //weight: 5
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_5_*) and 4 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Ransom_MSIL_Thanos_DC_2147779025_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:MSIL/Thanos.DC!MTB"
        threat_id = "2147779025"
        type = "Ransom"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Thanos"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "WorkerCrypter2" ascii //weight: 1
        $x_1_2 = "Encrypt2" ascii //weight: 1
        $x_1_3 = "ToBase64String" ascii //weight: 1
        $x_1_4 = "DecodeHuffman" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_MSIL_Thanos_MK_2147805138_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:MSIL/Thanos.MK!MTB"
        threat_id = "2147805138"
        type = "Ransom"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Thanos"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "SW5mb3JtYXRpb24uLi4=" wide //weight: 1
        $x_2_2 = "QWxsIHlvdXIgZmlsZXMgYXJlIHNlY3VyZWQsIHBsZWFzZSByZWFkIHRoZSB0ZXh0IG5vdGUgbG9jYXRlZCBpbiB5b3VyIGRlc2t0b3AuLi4=" wide //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


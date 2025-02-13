rule Ransom_MSIL_ReviL_DA_2147773260_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:MSIL/ReviL.DA!MTB"
        threat_id = "2147773260"
        type = "Ransom"
        platform = "MSIL: .NET intermediate language scripts"
        family = "ReviL"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Povlsomware" ascii //weight: 1
        $x_1_2 = "Encrypted" ascii //weight: 1
        $x_1_3 = "RansomeviL" ascii //weight: 1
        $x_1_4 = "Win32_ShadowCopy" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


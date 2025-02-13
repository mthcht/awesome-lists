rule Trojan_MSIL_ArtemisMSILLoader_EM_2147845756_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/ArtemisMSILLoader.EM!MTB"
        threat_id = "2147845756"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "ArtemisMSILLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "cleaning.homesecuritypc.com/packages" wide //weight: 1
        $x_1_2 = "WebRequest" ascii //weight: 1
        $x_1_3 = "NetworkCredential" ascii //weight: 1
        $x_1_4 = "WebHeaderCollection" ascii //weight: 1
        $x_1_5 = "CopyFromScreen" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_ArtemisMSILLoader_EH_2147846273_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/ArtemisMSILLoader.EH!MTB"
        threat_id = "2147846273"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "ArtemisMSILLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Hjdylzrfqmqaqasxd.Ndcxslchn" ascii //weight: 1
        $x_1_2 = "ezMxYzgyZjJlLWI3YjgtNDdkZS1hNGIyLTZjYTFiYTRjMjg1MX0sIEN1bHR1cmU9bmV1dHJhbCwgUHVibGljS2V5VG9rZW49M2U1NjM1MDY5M2Y3MzU1ZQ==" ascii //weight: 1
        $x_1_3 = "Izhitypvzr.exe" ascii //weight: 1
        $x_1_4 = "add_ResourceResolve" ascii //weight: 1
        $x_1_5 = "GetManifestResourceNames" ascii //weight: 1
        $x_1_6 = "CreateDecryptor" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


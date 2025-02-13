rule Trojan_MSIL_MBRDestroy_RDB_2147852982_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/MBRDestroy.RDB!MTB"
        threat_id = "2147852982"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "MBRDestroy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "7f69ff56-ee43-4679-bf24-83b375ac3921" ascii //weight: 1
        $x_1_2 = "OutSost Service Driver" ascii //weight: 1
        $x_1_3 = "DisableCMD" wide //weight: 1
        $x_1_4 = "DisableRegistryTools" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


rule Ransom_MSIL_DelShad_DA_2147772563_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:MSIL/DelShad.DA!MTB"
        threat_id = "2147772563"
        type = "Ransom"
        platform = "MSIL: .NET intermediate language scripts"
        family = "DelShad"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "L0MgdnNzYWRtaW4uZXhlIGRlbGV0ZSBzaGFkb3dzIC9hbGwgL1F1aWV0" ascii //weight: 1
        $x_1_2 = "L0MgQmNkZWRpdC5leGUgL3NldCB7ZGVmYXVsdH0gcmVjb3ZlcnllbmFibGVkIG5v" ascii //weight: 1
        $x_1_3 = "EncryptedKey" ascii //weight: 1
        $x_1_4 = "EncryptedFileName" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


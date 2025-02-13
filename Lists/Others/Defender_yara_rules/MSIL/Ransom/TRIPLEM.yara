rule Ransom_MSIL_TRIPLEM_DA_2147766855_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:MSIL/TRIPLEM.DA!MTB"
        threat_id = "2147766855"
        type = "Ransom"
        platform = "MSIL: .NET intermediate language scripts"
        family = "TRIPLEM"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "L0MgdnNzYWRtaW4uZXhlIGRlbGV0ZSBzaGFkb3dzIC9hbGwgL1F1aWV0" ascii //weight: 1
        $x_1_2 = "VFJJUExFTShNTU0pIFJFQk9STiBSQU5TT01XQVJFIHY0" ascii //weight: 1
        $x_1_3 = "DropShit.exe" ascii //weight: 1
        $x_1_4 = "DECRYPT_FILES.txt" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


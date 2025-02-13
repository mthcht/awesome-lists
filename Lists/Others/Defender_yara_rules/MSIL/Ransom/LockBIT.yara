rule Ransom_MSIL_LockBIT_DC_2147900146_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:MSIL/LockBIT.DC!MTB"
        threat_id = "2147900146"
        type = "Ransom"
        platform = "MSIL: .NET intermediate language scripts"
        family = "LockBIT"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "9"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "LockBIT" ascii //weight: 1
        $x_1_2 = "Encrypt" ascii //weight: 1
        $x_1_3 = "ReadAllBytes" ascii //weight: 1
        $x_1_4 = "GetLogicalDrives" ascii //weight: 1
        $x_1_5 = "GetDirectories" ascii //weight: 1
        $x_1_6 = "GetFiles" ascii //weight: 1
        $x_1_7 = "Exception" ascii //weight: 1
        $x_1_8 = "FromBase64String" ascii //weight: 1
        $x_1_9 = "ToBase64String" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


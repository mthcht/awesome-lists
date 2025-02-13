rule Ransom_MSIL_CORNY_DA_2147906692_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:MSIL/CORNY.DA!MTB"
        threat_id = "2147906692"
        type = "Ransom"
        platform = "MSIL: .NET intermediate language scripts"
        family = "CORNY"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "24"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "Ransom.Form1.resources" ascii //weight: 10
        $x_10_2 = "Ransom.Properties.Resources" ascii //weight: 10
        $x_1_3 = "fileEncrypted" ascii //weight: 1
        $x_1_4 = "FromBase64String" ascii //weight: 1
        $x_1_5 = "GetDrives" ascii //weight: 1
        $x_1_6 = ".root" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


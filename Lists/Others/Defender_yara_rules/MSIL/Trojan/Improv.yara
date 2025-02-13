rule Trojan_MSIL_Improv_A_2147773034_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Improv.A"
        threat_id = "2147773034"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Improv"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "7e1aa602-16dc-451a-8e54-17c9f959a19c" ascii //weight: 1
        $x_1_2 = "Copyright ImprovPose 2021" ascii //weight: 1
        $x_1_3 = "http://tensorflow.org/docs/" wide //weight: 1
        $x_1_4 = "Train model" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


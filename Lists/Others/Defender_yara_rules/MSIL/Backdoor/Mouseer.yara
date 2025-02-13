rule Backdoor_MSIL_Mouseer_A_2147708188_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:MSIL/Mouseer.A"
        threat_id = "2147708188"
        type = "Backdoor"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Mouseer"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "11"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "$69afcc05-a805-44ba-b255-616c2d2730e5" ascii //weight: 10
        $x_1_2 = {00 64 72 75 6d 73 61 6d 6f 72 2e 65 78 65 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


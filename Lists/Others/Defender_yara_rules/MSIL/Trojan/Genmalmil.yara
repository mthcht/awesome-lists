rule Trojan_MSIL_Genmalmil_2147708949_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Genmalmil"
        threat_id = "2147708949"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Genmalmil"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {41 64 6f 62 65 20 44 6f 77 6e 6c 6f 61 64 20 4d 61 6e 61 67 65 72 00}  //weight: 1, accuracy: High
        $x_1_2 = "Powered by SmartAssembly" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


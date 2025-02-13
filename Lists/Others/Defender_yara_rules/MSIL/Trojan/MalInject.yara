rule Trojan_MSIL_MalInject_B_2147766893_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/MalInject.B!MTB"
        threat_id = "2147766893"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "MalInject"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {6d 61 6c 68 65 75 72 65 75 78 00 43 6f 70 79 41 72 72 61 79 00 47 65 74 45 6e 74 72 79 41 73 73 65 6d 62 6c 79 00 42 6c 6f 63 6b 43 6f 70 79}  //weight: 1, accuracy: High
        $x_1_2 = {49 6e 76 6f 6b 65 4d 65 6d 62 65 72 00 53 70 65 63 69 61 6c 46 6f 6c 64 65 72}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


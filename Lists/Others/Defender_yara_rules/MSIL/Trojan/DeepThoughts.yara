rule Trojan_MSIL_DeepThoughts_A_2147973625_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/DeepThoughts.A!dha"
        threat_id = "2147973625"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "DeepThoughts"
        severity = "Critical"
        info = "dha: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "ynfgPunatrGvzr" wide //weight: 1
        $x_1_2 = "pbzznaqvq" wide //weight: 1
        $x_1_3 = "########## {0} {1:yyyy:M:dd,HH:mm:ss}" wide //weight: 1
        $x_1_4 = "\"{0}\":\"{1}\", \"{2}\":\"{3:yyyy:M:dd,HH:mm:ss}" wide //weight: 1
        $x_1_5 = "wrong market type: " wide //weight: 1
        $x_1_6 = "Error creating scask: " wide //weight: 1
    condition:
        (filesize < 20MB) and
        (2 of ($x*))
}


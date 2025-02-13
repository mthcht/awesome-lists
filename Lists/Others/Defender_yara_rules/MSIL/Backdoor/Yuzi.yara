rule Backdoor_MSIL_Yuzi_A_2147655956_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:MSIL/Yuzi.A"
        threat_id = "2147655956"
        type = "Backdoor"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Yuzi"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {5c 59 6f 6f 7a 79 53 65 72 76 65 72 2e 70 64 62 00}  //weight: 1, accuracy: High
        $x_1_2 = "YoozyServer" wide //weight: 1
        $x_1_3 = "netcl_end" wide //weight: 1
        $x_1_4 = "28137" wide //weight: 1
        $x_1_5 = "screenshot" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (4 of ($x*))
}


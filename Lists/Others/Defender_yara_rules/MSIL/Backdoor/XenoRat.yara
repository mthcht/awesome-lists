rule Backdoor_MSIL_XenoRat_BSA_2147927609_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:MSIL/XenoRat.BSA!MTB"
        threat_id = "2147927609"
        type = "Backdoor"
        platform = "MSIL: .NET intermediate language scripts"
        family = "XenoRat"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "15"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "xeno rat client" ascii //weight: 10
        $x_5_2 = {1b 30 06 00 84 0b 00 00 10 00 00 11 12 00 14 7d 04 00 00 04 14 0b 72 64 05 00 70 0c 08 18 28 32 00 00 0a 28 33 00 00 0a 16 28 34 00 00 0a 26 21 00 60 40 00 00 00 00 00 e0 0d 20 b7 50 00 00 13 04 11 04 8d}  //weight: 5, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_MSIL_XenoRat_BSA_2147927609_1
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:MSIL/XenoRat.BSA!MTB"
        threat_id = "2147927609"
        type = "Backdoor"
        platform = "MSIL: .NET intermediate language scripts"
        family = "XenoRat"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "22"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "xeno rat client" ascii //weight: 10
        $x_10_2 = "xeno_rat_client" ascii //weight: 10
        $x_10_3 = "\\xeno-rat\\Plugins" ascii //weight: 10
        $x_6_4 = "SendAsync" ascii //weight: 6
        $x_6_5 = "IAsyncStateMachine" ascii //weight: 6
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_10_*) and 2 of ($x_6_*))) or
            ((2 of ($x_10_*) and 1 of ($x_6_*))) or
            ((3 of ($x_10_*))) or
            (all of ($x*))
        )
}

rule Backdoor_MSIL_XenoRat_HB_2147949988_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:MSIL/XenoRat.HB!MTB"
        threat_id = "2147949988"
        type = "Backdoor"
        platform = "MSIL: .NET intermediate language scripts"
        family = "XenoRat"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "16"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "<socket>5__" ascii //weight: 1
        $x_1_2 = "LASTINPUTINFO" ascii //weight: 1
        $x_2_3 = {53 65 6e 64 41 73 79 6e 63 00 52 65 63 65 69 76 65 41 73 79 6e 63 00 46 72 6f 6d 41 73 79 6e 63 00 43 6f 6e 6e 65 63 74 41 73 79 6e 63 00 4c 6f 63 61 6c 41 6c 6c 6f 63}  //weight: 2, accuracy: High
        $x_1_4 = {47 65 74 57 69 6e 64 6f 77 54 68 72 65 61 64 50 72 6f 63 65 73 73 49 64 00 47 65 74 50 72 6f 63 65 73 73 42 79 49 64 00}  //weight: 1, accuracy: High
        $x_1_5 = "get_UserName" ascii //weight: 1
        $x_10_6 = {67 65 74 5f 49 73 41 74 74 61 63 68 65 64 00 67 65 74 5f 43 6f 6e 6e 65 63 74 65 64 00 41 77 61 69 74 55 6e 73 61 66 65 4f 6e 43 6f 6d 70 6c 65 74 65 64 00 67 65 74 5f 49 73 43 6f 6d 70 6c 65 74 65 64}  //weight: 10, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


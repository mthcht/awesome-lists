rule Trojan_MSIL_Scrami_GPA_2147902462_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Scrami.GPA!MTB"
        threat_id = "2147902462"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Scrami"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {53 00 55 00 56 00 59 00 49 00 43 00 68 00 4f 00 5a 00 58 00 63 00 74 00 54 00 32 00 4a 00 71 00 5a 00 57 00 4e 00 30 00 49 00 45 00 35 00 6c 00 64 00 43 00 35}  //weight: 2, accuracy: High
        $x_5_2 = {63 00 33 00 52 00 31 00 5a 00 47 00 56 00 75 00 64 00 43 00 31 00 32 00 62 00 32 00 6c 00 6a 00 5a 00 53 00 35 00 6a 00 62 00 32 00 30 00 76 00 59 00 58 00 42 00 70 00 4c 00 32 00 64 00 6c 00 64 00 46 00 39 00 77 00 63 00 31 00 39 00 73 00 62 00 79 00 49 00 70}  //weight: 5, accuracy: High
        $x_5_3 = {63 00 33 00 52 00 31 00 5a 00 47 00 56 00 75 00 64 00 43 00 31 00 32 00 62 00 32 00 6c 00 6a 00 5a 00 53 00 35 00 6a 00 62 00 32 00 30 00 76 00 59 00 58 00 42 00 70 00 4c 00 32 00 64 00 6c 00 64 00 46 00 39 00 77 00 63 00 79 00 49 00 70}  //weight: 5, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_5_*) and 1 of ($x_2_*))) or
            ((2 of ($x_5_*))) or
            (all of ($x*))
        )
}


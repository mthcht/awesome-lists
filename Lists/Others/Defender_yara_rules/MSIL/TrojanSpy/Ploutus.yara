rule TrojanSpy_MSIL_Ploutus_A_2147686271_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:MSIL/Ploutus.gen!A"
        threat_id = "2147686271"
        type = "TrojanSpy"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Ploutus"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "110"
        strings_accuracy = "High"
    strings:
        $x_100_1 = {50 6c 6f 75 74 75 73 53 65 72 76 69 63 65 2e 4e 43 52 2e 72 65 73 6f 75 72 63 65 73 00 50 6c 6f 75 74 75 73 53 65 72 76 69 63 65 2e 50 72 6f 70 65 72 74 69 65 73 2e 52 65 73 6f 75 72 63 65 73 2e 72 65 73 6f 75 72 63 65 73 00 50 6c 6f 75 74 75 73 53 65 72 76 69 63 65 2e 50 72 6f 6a 65 63 74 49 6e 73 74 61 6c 6c 65 72 2e 72 65 73 6f 75 72 63 65 73 00}  //weight: 100, accuracy: High
        $x_10_2 = {50 6c 6f 75 74 75 73 53 65 72 76 69 63 65 2e 65 78 65 00 50 6c 6f 75 74 75 73 53 65 72 76 69 63 65 00 6d 73 63 6f 72 6c 69 62 00}  //weight: 10, accuracy: High
        $x_100_3 = {50 6c 6f 75 74 6f 73 2e 50 72 6f 70 65 72 74 69 65 73 2e 52 65 73 6f 75 72 63 65 73 2e 72 65 73 6f 75 72 63 65 73 00 50 6c 6f 75 74 6f 73 2e 50 61 6e 65 6c 2e 72 65 73 6f 75 72 63 65 73 00}  //weight: 100, accuracy: High
        $x_10_4 = {50 6c 6f 75 74 6f 73 2e 65 78 65 00 50 6c 6f 75 74 6f 73 00 6d 73 63 6f 72 6c 69 62 00}  //weight: 10, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_100_*) and 1 of ($x_10_*))) or
            ((2 of ($x_100_*))) or
            (all of ($x*))
        )
}


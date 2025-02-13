rule Trojan_MSIL_BXRat_HNB_2147923007_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/BXRat.HNB!MTB"
        threat_id = "2147923007"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "BXRat"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "30"
        strings_accuracy = "High"
    strings:
        $x_15_1 = "DesableTaskMgnEscalaLayout" ascii //weight: 15
        $x_15_2 = {5d 00 5b 44 41 43 5d 5f 43 4f 4e 4b 45 52 5f 5b}  //weight: 15, accuracy: High
        $x_15_3 = {20 04 51 00 3e 05 26 04 51 00 40 05 24 04 51 00 44 05 28 04 51 00 46 05 2a 04 52 00 4a 05 2c 04}  //weight: 15, accuracy: High
        $x_15_4 = {00 41 62 72 69 72 4e 61 76 65 67 61 64 6f 72 00 75 72 6c 00}  //weight: 15, accuracy: High
        $x_15_5 = "iFjBgxx4VOc0odj+S6y6t0X" wide //weight: 15
        $x_15_6 = {53 79 73 74 65 6d 2e 53 65 63 75 72 69 74 79 00 57 69 6e 64 6f 77 73 49 64 65 6e 74 69 74 79 00 45 6d 70 74 79 00 47 65 74 50 72 6f 70 65 72 74 79 00 64 69 72 74 79}  //weight: 15, accuracy: High
        $x_15_7 = {49 53 65 72 69 61 6c 69 7a 65 72 50 72 6f 78 79 00 61 70 70 6c 79 4e 65 74 4f 62 6a 65 63 74 50 72 6f 78 79 00 70 72 6f 78 79 00 6b 65 79 79}  //weight: 15, accuracy: High
        $x_15_8 = {3c 4d 6f 64 75 6c 65 3e 00 53 65 74 57 69 6e 64 6f 77 4c 6f 6e 67 41 00}  //weight: 15, accuracy: High
        $x_15_9 = {67 65 74 5f 49 56 00 73 65 74 5f 49 56 00 47 65 6e 65 72 61 74 65 49 56 00}  //weight: 15, accuracy: High
    condition:
        (filesize < 20MB) and
        (2 of ($x*))
}


rule Backdoor_MSIL_Logedrut_A_2147695288_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:MSIL/Logedrut.A"
        threat_id = "2147695288"
        type = "Backdoor"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Logedrut"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "28"
        strings_accuracy = "High"
    strings:
        $x_16_1 = "SharpServer.exe" ascii //weight: 16
        $x_2_2 = {46 72 6f 6d 42 61 73 65 36 34 53 74 72 69 6e 67 00 43 72 65 61 74 65 44 65 63 72 79 70 74 6f 72}  //weight: 2, accuracy: High
        $x_2_3 = {67 65 74 5f 41 62 73 6f 6c 75 74 65 55 72 69 00 67 65 74 5f 45 78 65 63 75 74 61 62 6c 65 50 61 74 68}  //weight: 2, accuracy: High
        $x_2_4 = {47 65 74 44 72 69 76 65 73 00 67 65 74 5f 49 73 52 65 61 64 79}  //weight: 2, accuracy: High
        $x_2_5 = "step=1&id=" wide //weight: 2
        $x_2_6 = "buffertype=" wide //weight: 2
        $x_2_7 = "{{\"d\":\"{0}\",\"ts\":{1},\"fs\":{2},\"dt\":{3}}}" wide //weight: 2
        $x_2_8 = "&startpos=" wide //weight: 2
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_16_*) and 6 of ($x_2_*))) or
            (all of ($x*))
        )
}


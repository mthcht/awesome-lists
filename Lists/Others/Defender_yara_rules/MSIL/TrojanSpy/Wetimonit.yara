rule TrojanSpy_MSIL_Wetimonit_A_2147697413_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:MSIL/Wetimonit.A"
        threat_id = "2147697413"
        type = "TrojanSpy"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Wetimonit"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "9"
        strings_accuracy = "High"
    strings:
        $x_6_1 = {77 65 74 00 63 66 00 70 61 73 73 00 52 75 6e 41 53 53}  //weight: 6, accuracy: High
        $x_2_2 = {61 64 64 5f 53 68 75 74 64 6f 77 6e 00 45 78 69 74}  //weight: 2, accuracy: High
        $x_2_3 = {49 45 4d 6f 6e 69 74 6f 72 00 49 45 4d 6f 6e 69 74 6f 72 2e 65 78 65}  //weight: 2, accuracy: High
        $x_2_4 = "obj\\Release\\IEMonitor" ascii //weight: 2
        $x_1_5 = {73 65 74 5f 53 68 6f 77 49 6e 54 61 73 6b 62 61 72 00 73 65 74 5f 4f 70 61 63 69 74 79}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_6_*) and 1 of ($x_2_*) and 1 of ($x_1_*))) or
            ((1 of ($x_6_*) and 2 of ($x_2_*))) or
            (all of ($x*))
        )
}


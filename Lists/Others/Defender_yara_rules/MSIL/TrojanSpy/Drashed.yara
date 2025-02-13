rule TrojanSpy_MSIL_Drashed_A_2147693208_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:MSIL/Drashed.A"
        threat_id = "2147693208"
        type = "TrojanSpy"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Drashed"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "H75HTR703-" wide //weight: 1
        $x_1_2 = "\\Acitivitylog.xml" wide //weight: 1
        $x_1_3 = "Ping Disconnect......" wide //weight: 1
        $x_1_4 = "*DS_MUTEX-" ascii //weight: 1
        $x_1_5 = {12 84 fa 3f 82 a3 9f 9a 7d}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


rule TrojanSpy_MSIL_Cologger_A_2147645362_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:MSIL/Cologger.A"
        threat_id = "2147645362"
        type = "TrojanSpy"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Cologger"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "dbstealer" ascii //weight: 1
        $x_1_2 = "stealersend" ascii //weight: 1
        $x_1_3 = "CooLogger" wide //weight: 1
        $x_1_4 = "*logonly*" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


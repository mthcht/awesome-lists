rule Ransom_MSIL_SatQueen_2147750147_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:MSIL/SatQueen!MSR"
        threat_id = "2147750147"
        type = "Ransom"
        platform = "MSIL: .NET intermediate language scripts"
        family = "SatQueen"
        severity = "Critical"
        info = "MSR: Microsoft Security Response"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "SaveTheQueen.exe" ascii //weight: 1
        $x_1_2 = "PowerShell" ascii //weight: 1
        $x_1_3 = "PS2EXE_Host" wide //weight: 1
        $x_1_4 = "FromBase64String" ascii //weight: 1
        $x_1_5 = "c3RhcnQgY21kLmV4ZQ0KJHByb2NpZD1HZXQtUHJvY2VzcyAtTmFtZSBjbWQqICB8c2VsZWN0IC1leHBhbmQgaWQNCg0KJ" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


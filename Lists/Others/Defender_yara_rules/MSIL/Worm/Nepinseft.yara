rule Worm_MSIL_Nepinseft_A_2147640902_0
{
    meta:
        author = "defender2yara"
        detection_name = "Worm:MSIL/Nepinseft.A"
        threat_id = "2147640902"
        type = "Worm"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Nepinseft"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "<h1>MasterKey Logs of" wide //weight: 1
        $x_1_2 = "-Information of Infected PC----" wide //weight: 1
        $x_1_3 = "New PC Infected" wide //weight: 1
        $x_1_4 = "MasterKey_Stub.Resources" ascii //weight: 1
        $x_1_5 = "http://whatismyip.com/automation/n09230945.asp" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Worm_MSIL_Nepinseft_B_2147640903_0
{
    meta:
        author = "defender2yara"
        detection_name = "Worm:MSIL/Nepinseft.B"
        threat_id = "2147640903"
        type = "Worm"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Nepinseft"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "UEFTU1dPUkQ6IA==" ascii //weight: 1
        $x_1_2 = "TmV3IFBDIEluZmVjdGVkIA==" ascii //weight: 1
        $x_1_3 = "aHR0cDovL3doYXRpc215aXAuY29tL2F1dG9tYXRpb24vbjA5MjMwOTQ1LmFzcA=" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


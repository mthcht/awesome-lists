rule TrojanSpy_MSIL_Flunuceo_A_2147688610_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:MSIL/Flunuceo.A"
        threat_id = "2147688610"
        type = "TrojanSpy"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Flunuceo"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "ExecuteAndSend" ascii //weight: 1
        $x_1_2 = "DecryptDomains" ascii //weight: 1
        $x_1_3 = "CheckKey_Elapsed" ascii //weight: 1
        $x_1_4 = "CaptureScreen" ascii //weight: 1
        $x_1_5 = "SendImage" ascii //weight: 1
        $x_1_6 = "InfectionPath" ascii //weight: 1
        $x_1_7 = "KillProcess" ascii //weight: 1
        $x_1_8 = "Rootkit" ascii //weight: 1
        $x_1_9 = "getGoogleAccount" ascii //weight: 1
        $x_1_10 = "getMsnTalks" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (8 of ($x*))
}

rule TrojanSpy_MSIL_Flunuceo_B_2147725055_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:MSIL/Flunuceo.B!bit"
        threat_id = "2147725055"
        type = "TrojanSpy"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Flunuceo"
        severity = "Critical"
        info = "bit: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "YlhWc2RHaz0=$aHR0cDovL2ZyZWVnZW9pcC5uZXQvanNvbi8=" ascii //weight: 2
        $x_1_2 = "UHJvY2Vzc05hbWU=" ascii //weight: 1
        $x_1_3 = "U2hpZnRLZXlEb3du" ascii //weight: 1
        $x_2_4 = "Y21kLmV4ZSAvayBwaW5nIDAgJiBkZWwgIg==" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 2 of ($x_1_*))) or
            ((2 of ($x_2_*))) or
            (all of ($x*))
        )
}


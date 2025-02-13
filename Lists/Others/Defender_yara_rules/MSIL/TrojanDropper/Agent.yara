rule TrojanDropper_MSIL_Agent_A_2147626399_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:MSIL/Agent.A"
        threat_id = "2147626399"
        type = "TrojanDropper"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Agent"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {44 72 6f 70 45 58 45 00 45 58 45 6e 61 6d 65}  //weight: 2, accuracy: High
        $x_2_2 = {61 62 63 64 65 00 61 62 63 64 65 2e 65 78 65}  //weight: 2, accuracy: High
        $x_1_3 = {28 23 00 00 0a 14 72 01 00 00 70 28 12 00 00 06 ?? ?? 16 28 11 00 00 06 26 72 09 00 00 70 72 25 00 00 70 28 24 00 00 0a 28 11 00 00 0a}  //weight: 1, accuracy: Low
        $x_1_4 = {06 16 1f 4d 9c 06}  //weight: 1, accuracy: High
        $x_1_5 = {06 17 1f 5a 9c 06}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 3 of ($x_1_*))) or
            ((2 of ($x_2_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule TrojanDropper_MSIL_Agent_E_2147646244_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:MSIL/Agent.E"
        threat_id = "2147646244"
        type = "TrojanDropper"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Agent"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "11"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "antiSandboxie" ascii //weight: 2
        $x_3_2 = "disableWebsiteBlocker" ascii //weight: 3
        $x_3_3 = "fakeErrorMessage" ascii //weight: 3
        $x_3_4 = "\" goto Repeat" wide //weight: 3
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


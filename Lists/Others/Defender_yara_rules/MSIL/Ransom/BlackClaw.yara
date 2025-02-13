rule Ransom_MSIL_BlackClaw_DEA_2147756614_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:MSIL/BlackClaw.DEA!MTB"
        threat_id = "2147756614"
        type = "Ransom"
        platform = "MSIL: .NET intermediate language scripts"
        family = "BlackClaw"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "RECOVER YOUR FILES.hta" ascii //weight: 1
        $x_1_2 = "RECOVER YOUR FILES.txt" ascii //weight: 1
        $x_1_3 = ".[{0}].bclaw" ascii //weight: 1
        $x_1_4 = ".bclaw" ascii //weight: 1
        $x_1_5 = "https://claw.black/" ascii //weight: 1
        $x_1_6 = "/C choice /C Y /N /D Y /T 3 & Del \"" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


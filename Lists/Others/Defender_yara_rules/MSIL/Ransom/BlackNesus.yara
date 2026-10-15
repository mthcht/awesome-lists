rule Ransom_MSIL_BlackNesus_C_2147980324_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:MSIL/BlackNesus.C!MTB"
        threat_id = "2147980324"
        type = "Ransom"
        platform = "MSIL: .NET intermediate language scripts"
        family = "BlackNesus"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "/sc once /st 00:00 /ru SYSTEM /rl HIGHEST /f" ascii //weight: 1
        $x_1_2 = "targets.txt" ascii //weight: 1
        $x_1_3 = "delete shadows /all /quiet" ascii //weight: 1
        $x_1_4 = "shadowcopy delete" ascii //weight: 1
        $x_1_5 = "/set {default} recoveryenabled No" ascii //weight: 1
        $x_1_6 = "=== BLACK NENUS ATTACK ===" ascii //weight: 1
        $x_1_7 = "HOW_TO_DECRYPT.txt" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


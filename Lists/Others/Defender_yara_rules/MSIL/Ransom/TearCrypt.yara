rule Ransom_MSIL_TearCrypt_PAA_2147809446_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:MSIL/TearCrypt.PAA!MTB"
        threat_id = "2147809446"
        type = "Ransom"
        platform = "MSIL: .NET intermediate language scripts"
        family = "TearCrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "teardrop.pdb" ascii //weight: 1
        $x_1_2 = "DisableTaskManager" ascii //weight: 1
        $x_1_3 = "komputer ma virusa- kt" ascii //weight: 1
        $x_1_4 = "<p>hackthedev/teardrop</p>" ascii //weight: 1
        $x_1_5 = "teardrop.Properties.Resources" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


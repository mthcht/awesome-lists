rule Ransom_MSIL_Slankcrypt_DA_2147772409_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:MSIL/Slankcrypt.DA!MTB"
        threat_id = "2147772409"
        type = "Ransom"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Slankcrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "ALL YOUR FILES ARE ENCRYPTED" ascii //weight: 1
        $x_1_2 = "DisableTaskMgr" ascii //weight: 1
        $x_1_3 = "DEAR INFECTED CLIENTS" ascii //weight: 1
        $x_1_4 = ".slank" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


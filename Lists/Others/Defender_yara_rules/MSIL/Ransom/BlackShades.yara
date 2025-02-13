rule Ransom_MSIL_BlackShades_A_2147716526_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:MSIL/BlackShades.A!bit"
        threat_id = "2147716526"
        type = "Ransom"
        platform = "MSIL: .NET intermediate language scripts"
        family = "BlackShades"
        severity = "Critical"
        info = "bit: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "BlackShades Crypter" ascii //weight: 1
        $x_1_2 = "Your files were protected by a strong encryption" ascii //weight: 1
        $x_1_3 = "Bitcoin to this account" ascii //weight: 1
        $x_1_4 = "The infection encrypts everything" ascii //weight: 1
        $x_1_5 = "DisableTaskMgr" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (4 of ($x*))
}


rule Ransom_Linux_Monti_A_2147853037_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Linux/Monti.A!MTB"
        threat_id = "2147853037"
        type = "Ransom"
        platform = "Linux: Linux platform"
        family = "Monti"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "14"
        strings_accuracy = "High"
    strings:
        $x_5_1 = "MONTI strain" ascii //weight: 5
        $x_1_2 = "--vmkill" ascii //weight: 1
        $x_1_3 = "EncryptedContentInfo" ascii //weight: 1
        $x_1_4 = "encryptedData" ascii //weight: 1
        $x_1_5 = "vm-list" ascii //weight: 1
        $x_5_6 = ".monti" ascii //weight: 5
        $x_5_7 = ".puuuk" ascii //weight: 5
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_5_*) and 4 of ($x_1_*))) or
            ((3 of ($x_5_*))) or
            (all of ($x*))
        )
}


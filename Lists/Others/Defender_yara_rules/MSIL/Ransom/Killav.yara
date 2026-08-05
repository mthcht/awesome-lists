rule Ransom_MSIL_Killav_VD_2147975315_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:MSIL/Killav.VD!MTB"
        threat_id = "2147975315"
        type = "Ransom"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Killav"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "9"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "VICTIM_ID" ascii //weight: 2
        $x_2_2 = "schtasks" ascii //weight: 2
        $x_1_3 = "your files have been secured" ascii //weight: 1
        $x_1_4 = "encrypted files" ascii //weight: 1
        $x_2_5 = "contact" ascii //weight: 2
        $x_2_6 = "KILL" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (
            ((4 of ($x_2_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}


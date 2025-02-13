rule Ransom_Linux_FILocker_A_2147847335_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Linux/FILocker.A!MTB"
        threat_id = "2147847335"
        type = "Ransom"
        platform = "Linux: Linux platform"
        family = "FILocker"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "main.makeReadme.func" ascii //weight: 2
        $x_2_2 = "main.deleteSelf" ascii //weight: 2
        $x_1_3 = "main.walk-tramp0" ascii //weight: 1
        $x_1_4 = "main.TableToggleObf" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_2_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}


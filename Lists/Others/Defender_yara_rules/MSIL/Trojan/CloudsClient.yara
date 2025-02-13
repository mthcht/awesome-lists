rule Trojan_MSIL_CloudsClient_A_2147773979_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/CloudsClient.A!dha"
        threat_id = "2147773979"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "CloudsClient"
        severity = "Critical"
        info = "dha: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_4_1 = "fa666683-db26-476d-ae0a-2e1da13916db" ascii //weight: 4
        $x_1_2 = "CloudsApplication" wide //weight: 1
        $x_1_3 = ">> Failed to creation session:" wide //weight: 1
        $x_1_4 = "RenamePath No permission" wide //weight: 1
        $x_1_5 = "CreateDecryptor" ascii //weight: 1
        $x_1_6 = "Clouds.Properties.Resources" ascii //weight: 1
        $x_1_7 = "File upload started" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((4 of ($x_1_*))) or
            ((1 of ($x_4_*))) or
            (all of ($x*))
        )
}


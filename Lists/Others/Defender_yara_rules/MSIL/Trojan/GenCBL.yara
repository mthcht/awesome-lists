rule Trojan_MSIL_GenCBL_PACM_2147898717_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/GenCBL.PACM!MTB"
        threat_id = "2147898717"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "GenCBL"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "unknownspf.g.resources" ascii //weight: 1
        $x_3_2 = "ef245861-d797-4b9b-812a-85f47f1e2c68" wide //weight: 3
        $x_3_3 = "05d80ab7-efce-468c-a02b-80c27533dd21" wide //weight: 3
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_3_*) and 1 of ($x_1_*))) or
            ((2 of ($x_3_*))) or
            (all of ($x*))
        )
}


rule Spammer_MSIL_Yabam_A_2147637668_0
{
    meta:
        author = "defender2yara"
        detection_name = "Spammer:MSIL/Yabam.A"
        threat_id = "2147637668"
        type = "Spammer"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Yabam"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "YabmClient" ascii //weight: 1
        $x_1_2 = "U09GVFdBUkVcTWljcm9zb2Z0XFdpbmRvd3NcQ3VycmVudFZlcnNpb25cUnVu" wide //weight: 1
        $x_1_3 = "{TB_MSGID}" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


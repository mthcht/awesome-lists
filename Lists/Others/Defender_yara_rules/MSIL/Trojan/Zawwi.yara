rule Trojan_MSIL_Zawwi_A_2147706463_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Zawwi.A"
        threat_id = "2147706463"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Zawwi"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "SEtFWV9DVVJSRU5UX1VTRVJcU29mdHdhcmVcTWljcm9zb2Z0XFdpbmRvd3MgTlRcQ3VycmVudFZlcnNpb25cV2luZG93cw==" ascii //weight: 1
        $x_1_2 = "TG9hZA==" ascii //weight: 1
        $x_1_3 = "Y21kIC9jIA==" ascii //weight: 1
        $x_1_4 = "wizza.exe" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}


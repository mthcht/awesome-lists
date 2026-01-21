rule Trojan_MSIL_Negasteal_AYA_2147961462_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Negasteal.AYA!MTB"
        threat_id = "2147961462"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Negasteal"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "12"
        strings_accuracy = "High"
    strings:
        $x_7_1 = {00 06 11 18 6f 68 00 00 0a 13 19 11 19 09 d2 61 d2 13 19 11 19 09 d2 61 d2 13 19 00 00 11 18 17 58 13 18 11 18 19 06 6f 60 00 00 0a 28 69 00 00 0a fe 04 13 1a 11 1a 2d c7}  //weight: 7, accuracy: High
        $x_2_2 = "$C5E9A3F7-8D2B-4A6E-9F4C-7B1A5E8D3F6C" ascii //weight: 2
        $x_1_3 = "ParseBitmapChannels" ascii //weight: 1
        $x_1_4 = "UnwrapColorTriplet" ascii //weight: 1
        $x_1_5 = "screen_saver_v2.Form2.resources" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


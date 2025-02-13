rule Trojan_MSIL_Trigona_MBDH_2147844947_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Trigona.MBDH!MTB"
        threat_id = "2147844947"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Trigona"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {11 09 11 05 16 11 05 8e 69 6f ?? 00 00 0a 13 06 11 08 6f ?? 00 00 0a 11 09 6f ?? 00 00 0a de 24}  //weight: 1, accuracy: Low
        $x_1_2 = "e5fa87ec-c1c1-0882-9621-81263ac8ef91" ascii //weight: 1
        $x_1_3 = "uuuuuDDDD77777" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


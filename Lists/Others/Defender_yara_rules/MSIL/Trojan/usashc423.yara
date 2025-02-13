rule Trojan_MSIL_usashc423_RDB_2147845694_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/usashc423.RDB!MTB"
        threat_id = "2147845694"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "usashc423"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "cf05df14-c0d1-43dc-9cf9-aaa73636a338" ascii //weight: 1
        $x_2_2 = {11 06 11 07 11 05 11 07 6f 61 00 00 0a 20 3b 0e 00 00 61 d1 9d}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_usashc423_RDA_2147846503_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/usashc423.RDA!MTB"
        threat_id = "2147846503"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "usashc423"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "p8szzRng4TqgQkEZ5mD3kSkiQmopHcsRk0wSoJP6w/0=" wide //weight: 1
        $x_1_2 = "OKPZsjx47+6moiRZrqzqSSkUsmfa86dQIFAhs45VG196Th++" wide //weight: 1
        $x_1_3 = "8482f57da1ef4ef586436225d7a289d0" ascii //weight: 1
        $x_1_4 = "2a25c14cdd204ea7ac28c220c509e048" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


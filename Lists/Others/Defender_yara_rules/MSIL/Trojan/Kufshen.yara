rule Trojan_MSIL_Kufshen_A_2147691376_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Kufshen.A"
        threat_id = "2147691376"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Kufshen"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "LXBhc3N3b3JkPQ==" wide //weight: 1
        $x_1_2 = "aHR0cDovLzQ2LjE3Ljk3Ljg1L21pbmVyL" wide //weight: 1
        $x_1_3 = "RnJhbWVXb3JrXFxXb3JrZXJcXHdpbmluaWl0LmV4ZQ==" wide //weight: 1
        $x_1_4 = "L21pbmVyL2ZpbGVsaXN0LnR4dA==" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Kufshen_B_2147691377_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Kufshen.B"
        threat_id = "2147691377"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Kufshen"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "16"
        strings_accuracy = "High"
    strings:
        $x_4_1 = "V2luZG93c1xcVGVtcFxcd2ludXBkYXRlXFxtaW5lcg==" wide //weight: 4
        $x_4_2 = "V2luZG93c1xcVGVtcFxcd2ludXBkYXRlXFxtaW5lclxccnBjbWluZXItY3B1LmV4ZQ==" wide //weight: 4
        $x_4_3 = "V2luZG93c1xcVGVtcFxcd2ludXBkYXRlXFxtaW5lclxccGhvZW5peC5leGU=" wide //weight: 4
        $x_4_4 = "d2luaW5paXQuZXhlIC11cmw9aHR0cDovLw==" wide //weight: 4
        $x_8_5 = "btcguild.com:8332" wide //weight: 8
    condition:
        (filesize < 20MB) and
        (
            ((4 of ($x_4_*))) or
            ((1 of ($x_8_*) and 2 of ($x_4_*))) or
            (all of ($x*))
        )
}


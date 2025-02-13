rule TrojanProxy_MSIL_Banxpa_A_2147679667_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanProxy:MSIL/Banxpa.A"
        threat_id = "2147679667"
        type = "TrojanProxy"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Banxpa"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "132"
        strings_accuracy = "Low"
    strings:
        $x_100_1 = {78 75 70 61 (31|32|33|34|35|36|37|38|39|30) 00 78 75 70 61 (31|32|33|34|35|36|37|38|39|30)}  //weight: 100, accuracy: Low
        $x_10_2 = ".php?nomepc=" wide //weight: 10
        $x_10_3 = "&osName=" wide //weight: 10
        $x_10_4 = "rk.proxy.t" wide //weight: 10
        $x_1_5 = "var bra2 = " wide //weight: 1
        $x_1_6 = "var hsbc1 = " wide //weight: 1
        $x_1_7 = "var ban1 = " wide //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_100_*) and 3 of ($x_10_*) and 2 of ($x_1_*))) or
            (all of ($x*))
        )
}


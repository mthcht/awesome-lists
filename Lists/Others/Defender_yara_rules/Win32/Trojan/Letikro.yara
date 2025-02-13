rule Trojan_Win32_Letikro_A_2147633094_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Letikro.A"
        threat_id = "2147633094"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Letikro"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "!tickit!" ascii //weight: 2
        $x_2_2 = "!storage!" ascii //weight: 2
        $x_1_3 = "lego2.ini" ascii //weight: 1
        $x_1_4 = "LEGO_MUTEX2" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_2_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_Letikro_B_2147637565_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Letikro.B"
        threat_id = "2147637565"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Letikro"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "SOFTWARE\\Microsoft\\UDP\\c" ascii //weight: 2
        $x_2_2 = "/!raj.rorre:raj" ascii //weight: 2
        $x_2_3 = "lux.smrofkoohm/tnetnoc/smrofkoohm//:emorhc" ascii //weight: 2
        $x_3_4 = "Mimicker, FSB-POWER 2008-9" wide //weight: 3
    condition:
        (filesize < 20MB) and
        (
            ((3 of ($x_2_*))) or
            ((1 of ($x_3_*) and 1 of ($x_2_*))) or
            (all of ($x*))
        )
}


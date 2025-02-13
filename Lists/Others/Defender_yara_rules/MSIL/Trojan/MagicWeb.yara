rule Trojan_MSIL_MagicWeb_A_2147830064_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/MagicWeb.A!dha"
        threat_id = "2147830064"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "MagicWeb"
        severity = "Critical"
        info = "dha: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {09 08 11 04 8f 60 00 00 01 72 a3 04 00 70 28}  //weight: 1, accuracy: High
        $x_1_2 = {28 62 00 00 0a 6f 63 00 00 0a 26 11 04 17 58 13 04}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


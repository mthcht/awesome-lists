rule Trojan_MacOS_Rakkotonak_A_2147745030_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MacOS/Rakkotonak.A"
        threat_id = "2147745030"
        type = "Trojan"
        platform = "MacOS: "
        family = "Rakkotonak"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_MACHOHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8a 00 32 03 88 45 04 00 48 8b 45 ?? ?? ?? ?? ?? 88 45 ?? 48 8d 55 ?? b9 01 00 00 00 4c 89 e6 ff 15}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


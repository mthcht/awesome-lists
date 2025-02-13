rule Trojan_MacOS_Gebozamba_A_2147774922_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MacOS/Gebozamba.A"
        threat_id = "2147774922"
        type = "Trojan"
        platform = "MacOS: "
        family = "Gebozamba"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_MACHOHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {89 c2 c1 fa 1f c1 ea 1c 01 c2 83 e2 f0 89 c6 29 d6 8a 14 0e 30 94 05 ?? ?? ?? ?? 48 ff c0 48 83 f8 0c}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


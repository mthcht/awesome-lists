rule Trojan_MacOS_SugarLoader_AMTB_2147970350_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MacOS/SugarLoader!AMTB"
        threat_id = "2147970350"
        type = "Trojan"
        platform = "MacOS: "
        family = "SugarLoader"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_MACHOHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {48 85 d2 74 3d 48 89 d3 48 8d 45 f4 48 89 04 24 48 8d 45 e0 4c 8d 45 f0 4c 8d 4d e8 89 ca 48 89 c1 e8 a4 02 00 00 85 c0 75 1d 48 8b 7d e0 8b 75 f0 48 8b 55 e8 8b 4d f4 49 89 d8 e8 b1 03 00 00 eb 05}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


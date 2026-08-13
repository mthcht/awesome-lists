rule Trojan_MSIL_SeaMonkey_ATYB_2147976081_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/SeaMonkey.ATYB!MTB"
        threat_id = "2147976081"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "SeaMonkey"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_4_1 = {09 11 04 93 1f 61 32 0d 09 11 04 93 1f 7a fe 02 16 fe 01 2b 01 16 13 05 11 05 2c 17 09 11 04 09 11 04 93 1f 61 59 1f 0d 58 1f 1a 5d 1f 61 58 d1 9d 2b 31 09 11 04 93 1f 41 32 0d}  //weight: 4, accuracy: High
        $x_3_2 = {09 11 04 93 1f 5a fe 02 16 fe 01 2b 01 16 13 06 11 06 2c 15 09 11 04 09 11 04 93 1f 41 59 1f 0d 58 1f 1a 5d 1f 41 58 d1 9d 00 11 04 17 58 13 04 11 04 09 8e 69 fe 04 13 07 11 07 2d 87}  //weight: 3, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


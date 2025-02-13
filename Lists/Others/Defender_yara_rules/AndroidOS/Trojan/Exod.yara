rule Trojan_AndroidOS_Exod_B_2147786256_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:AndroidOS/Exod.B"
        threat_id = "2147786256"
        type = "Trojan"
        platform = "AndroidOS: Android operating system"
        family = "Exod"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "operatore.italia" ascii //weight: 2
        $x_1_2 = "/7e661733-e332-429a-a7e2-23649f27690f/" ascii //weight: 1
        $x_1_3 = "7acbff64-7a3a-4ebd-8997-4839b5937024" ascii //weight: 1
        $x_1_4 = {13 00 0a 00 23 01 d4 10 26 01 26 00 00 00 22 02 a3 0e 70 10 9f 72 02 00 12 00 6e 10 7d 72 05 00 0a 03 35 30 13 00 6e 20 67 72 05 00 0a 03 21 14 94 04 00 04 49 04 01 04 b7 43 8e 33 6e 20 a2 72 32 00 d8 00 00 10 28 ea 6e 10 b1 72 02 00 0c 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


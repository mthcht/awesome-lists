rule Trojan_MacOS_Shemala_A_2147752819_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MacOS/Shemala.A"
        threat_id = "2147752819"
        type = "Trojan"
        platform = "MacOS: "
        family = "Shemala"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_MACHOHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {48 89 4d f8 89 45 f4 48 89 75 e8 48 8d 85 bf df ff ff 48 8d 0d 48 02 00 00 ba 09 20 00 00 48 89 c7 48 89 ce}  //weight: 2, accuracy: High
        $x_3_2 = {48 b8 00 00 00 00 00 00 00 00 48 be 28 20 00 00 00 00 00 00 bf 07 00 00 00 41 b9 02 10 00 00 41 ba ff ff ff ff 89 bd b8 df ff ff 48 89 c7 44 8b 9d b8 df ff ff 44 89 da 44 89 c9 45 89 d0 49 89 c1}  //weight: 3, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


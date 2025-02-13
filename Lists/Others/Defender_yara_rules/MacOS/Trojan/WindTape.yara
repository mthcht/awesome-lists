rule Trojan_MacOS_WindTape_A_2147832998_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MacOS/WindTape.A"
        threat_id = "2147832998"
        type = "Trojan"
        platform = "MacOS: "
        family = "WindTape"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_MACHOHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {45 31 ff 31 ff be 01 00 00 00 ba 01 00 00 00 41 b8 08 00 00 00 48 89 d9 4c 8d 8d b8 fb ff ff 48 8d 85 c8 fb ff ff 50 68 00 04 00 00 48 8d 85 d0 fb ff ff 50 41 54 41 56 e8 cb 3b 00 00}  //weight: 2, accuracy: High
        $x_1_2 = "%@/%@.jpg" ascii //weight: 1
        $x_1_3 = "GenrateDeviceName" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


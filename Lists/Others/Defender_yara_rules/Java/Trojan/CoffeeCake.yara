rule Trojan_Java_CoffeeCake_A_2147981570_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Java/CoffeeCake.A"
        threat_id = "2147981570"
        type = "Trojan"
        platform = "Java: Java binaries (classes)"
        family = "CoffeeCake"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_JAVAHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {2a be bc 08 4d 03 3e 1d 2a be a2 ?? ?? 2c 1d 2a 1d 33 2b 1d 2b be 70 33 82 91 54 84 03 01 a7 ?? ?? 2c b0}  //weight: 5, accuracy: Low
        $x_5_2 = {2d 01 2c be 85 11 30 00 10 40 b9 ?? ?? 06 00 3a 04 19 04}  //weight: 5, accuracy: Low
        $x_5_3 = {19 04 09 2c 03 2c be b6 ?? ?? bb ?? ?? 59 b7 ?? ?? 3a 05 2d 01 09 19 04 01 03 19 05 b9 ?? ?? 08 00 3a 06 19 06}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (2 of ($x*))
}


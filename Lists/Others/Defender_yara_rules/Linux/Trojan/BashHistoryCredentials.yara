rule Trojan_Linux_BashHistoryCredentials_B_2147793582_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Linux/BashHistoryCredentials.B"
        threat_id = "2147793582"
        type = "Trojan"
        platform = "Linux: Linux platform"
        family = "BashHistoryCredentials"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "105"
        strings_accuracy = "Low"
    strings:
        $x_100_1 = {68 00 69 00 73 00 74 00 6f 00 72 00 79 00 27 02 02 00 7c 00 27 02 02 00 67 00 72 00 65 00 70 00}  //weight: 100, accuracy: Low
        $x_5_2 = "password" wide //weight: 5
        $x_5_3 = "pass" wide //weight: 5
        $x_5_4 = "pw" wide //weight: 5
        $x_5_5 = "key" wide //weight: 5
        $x_5_6 = "-p" wide //weight: 5
        $x_5_7 = "user" wide //weight: 5
        $x_5_8 = "credentials" wide //weight: 5
        $x_5_9 = "mysql" wide //weight: 5
        $x_5_10 = "telnet" wide //weight: 5
        $x_5_11 = "ssh" wide //weight: 5
        $x_5_12 = "root" wide //weight: 5
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_100_*) and 1 of ($x_5_*))) or
            (all of ($x*))
        )
}


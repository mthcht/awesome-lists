rule Backdoor_Linux_Ropys_A_2147824584_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Linux/Ropys.A!xp"
        threat_id = "2147824584"
        type = "Backdoor"
        platform = "Linux: Linux platform"
        family = "Ropys"
        severity = "Critical"
        info = "xp: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "WEBDOS" ascii //weight: 1
        $x_1_2 = "/cgi-bin/tree.php" ascii //weight: 1
        $x_1_3 = "/cgi-bin/contact.cgi" ascii //weight: 1
        $x_1_4 = "/cgi-sys/guestbook.cgi" ascii //weight: 1
        $x_1_5 = "/cgi-bin/php5-cgi" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (4 of ($x*))
}


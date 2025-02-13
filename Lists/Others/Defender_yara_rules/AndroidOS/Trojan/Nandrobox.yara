rule Trojan_AndroidOS_Nandrobox_A_2147928916_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:AndroidOS/Nandrobox.A"
        threat_id = "2147928916"
        type = "Trojan"
        platform = "AndroidOS: Android operating system"
        family = "Nandrobox"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "mobilehotdog.com/cnxmlrpc/xml.php" ascii //weight: 2
        $x_2_2 = "STRING_SUCWORD" ascii //weight: 2
        $x_2_3 = "STRING_FEECUE" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


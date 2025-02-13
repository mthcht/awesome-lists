rule Trojan_AndroidOS_SpamSold_A_2147678311_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:AndroidOS/SpamSold.A"
        threat_id = "2147678311"
        type = "Trojan"
        platform = "AndroidOS: Android operating system"
        family = "SpamSold"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "l0rdzs0ldierz.com" ascii //weight: 1
        $x_1_2 = "command.php?action=sent&number=" ascii //weight: 1
        $x_1_3 = "smsmessaging.Main" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


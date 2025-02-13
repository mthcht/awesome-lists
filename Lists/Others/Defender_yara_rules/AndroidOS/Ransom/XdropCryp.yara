rule Ransom_AndroidOS_XdropCryp_A_2147756539_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:AndroidOS/XdropCryp.A!MTB"
        threat_id = "2147756539"
        type = "Ransom"
        platform = "AndroidOS: Android operating system"
        family = "XdropCryp"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "Lcom/example/kico/myapplication/" ascii //weight: 2
        $x_2_2 = "/addslave.php" ascii //weight: 2
        $x_1_3 = "/ranso.php" ascii //weight: 1
        $x_1_4 = "/StartActivityOnBootReceiver;" ascii //weight: 1
        $x_1_5 = ".xdrop" ascii //weight: 1
        $x_1_6 = "your all photos and files are Encrypted" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 3 of ($x_1_*))) or
            ((2 of ($x_2_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}


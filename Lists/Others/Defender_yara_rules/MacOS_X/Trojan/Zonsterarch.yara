rule Trojan_MacOS_X_Zonsterarch_A_2147680311_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MacOS_X/Zonsterarch.A"
        threat_id = "2147680311"
        type = "Trojan"
        platform = "MacOS_X: "
        family = "Zonsterarch"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_MACHOHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "zipmonster.ru" ascii //weight: 2
        $x_1_2 = "rules: url= %@, smscount= %i" ascii //weight: 1
        $x_1_3 = "SMS for activation" ascii //weight: 1
        $x_1_4 = "onclick=function(){if(console){console.log('zm_smsinfo" ascii //weight: 1
        $x_1_5 = "zm_empay_link" ascii //weight: 1
        $x_1_6 = "zm_arcopen" ascii //weight: 1
        $x_1_7 = "cfg_archive_name" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((4 of ($x_1_*))) or
            ((1 of ($x_2_*) and 2 of ($x_1_*))) or
            (all of ($x*))
        )
}


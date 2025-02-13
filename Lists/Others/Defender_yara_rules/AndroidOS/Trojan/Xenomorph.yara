rule Trojan_AndroidOS_Xenomorph_B_2147843542_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:AndroidOS/Xenomorph.B"
        threat_id = "2147843542"
        type = "Trojan"
        platform = "AndroidOS: Android operating system"
        family = "Xenomorph"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "uewEbJ" ascii //weight: 1
        $x_1_2 = "CookieGrabberActivity" ascii //weight: 1
        $x_1_3 = "Lmeritoriousness/mollah/presser/" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


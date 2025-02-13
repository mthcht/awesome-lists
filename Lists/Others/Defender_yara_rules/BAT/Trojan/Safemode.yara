rule Trojan_BAT_Safemode_SA_2147907154_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:BAT/Safemode.SA"
        threat_id = "2147907154"
        type = "Trojan"
        platform = "BAT: Basic scripts"
        family = "Safemode"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "bcdedit" wide //weight: 1
        $x_1_2 = "/set" wide //weight: 1
        $x_1_3 = "safeboot" wide //weight: 1
        $x_1_4 = "minimal" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


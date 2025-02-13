rule Trojan_AndroidOS_Ermac_U_2147901922_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:AndroidOS/Ermac.U"
        threat_id = "2147901922"
        type = "Trojan"
        platform = "AndroidOS: Android operating system"
        family = "Ermac"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "updateinjectandlistapps" ascii //weight: 1
        $x_1_2 = "text2zzz" ascii //weight: 1
        $x_1_3 = "updateBotParamsl" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_AndroidOS_Ermac_IO_2147919236_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:AndroidOS/Ermac.IO"
        threat_id = "2147919236"
        type = "Trojan"
        platform = "AndroidOS: Android operating system"
        family = "Ermac"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "swapSmsMenager_Error" ascii //weight: 1
        $x_1_2 = "updateSettingsAndCommands" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


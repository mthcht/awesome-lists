rule Trojan_AndroidOS_Grifthorse_D_2147843752_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:AndroidOS/Grifthorse.D"
        threat_id = "2147843752"
        type = "Trojan"
        platform = "AndroidOS: Android operating system"
        family = "Grifthorse"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "to_lang_bg" ascii //weight: 1
        $x_1_2 = "textviewoText" ascii //weight: 1
        $x_1_3 = "i speak something" ascii //weight: 1
        $x_1_4 = "trasfactivity_webview" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_AndroidOS_Grifthorse_A_2147852037_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:AndroidOS/Grifthorse.A"
        threat_id = "2147852037"
        type = "Trojan"
        platform = "AndroidOS: Android operating system"
        family = "Grifthorse"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "Lcom/recdel/etdpro" ascii //weight: 2
        $x_2_2 = "Lcom/dslrcm/focpr1" ascii //weight: 2
        $x_2_3 = "tcEEDEu6uSHVLEfc4pxbq4" ascii //weight: 2
        $x_2_4 = "2HsiUpVrRsqGVVJKp5vPVC" ascii //weight: 2
        $x_1_5 = "open_wb=" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_2_*) and 1 of ($x_1_*))) or
            ((3 of ($x_2_*))) or
            (all of ($x*))
        )
}

rule Trojan_AndroidOS_Grifthorse_T_2147898984_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:AndroidOS/Grifthorse.T"
        threat_id = "2147898984"
        type = "Trojan"
        platform = "AndroidOS: Android operating system"
        family = "Grifthorse"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "CLEAR_HISTORY_TRIGGERS_ONCE" ascii //weight: 1
        $x_1_2 = "TestInstallInfo" ascii //weight: 1
        $x_1_3 = "CCallback" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


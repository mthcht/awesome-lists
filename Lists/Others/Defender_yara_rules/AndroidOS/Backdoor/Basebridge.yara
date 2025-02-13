rule Backdoor_AndroidOS_Basebridge_AB_2147796551_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:AndroidOS/Basebridge.AB"
        threat_id = "2147796551"
        type = "Backdoor"
        platform = "AndroidOS: Android operating system"
        family = "Basebridge"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "HoiprJbh9C519IF5HxiL9I0h8cMNuezDrebh7Ishz2M1ut3g9Nr20C35zxlpztVCzwuW0t3wztFIfxkRfcBbutLE" ascii //weight: 2
        $x_2_2 = "Lcom/android/battery/KillThreeSixZero" ascii //weight: 2
        $x_2_3 = "/sf/dna/Unzipping" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_AndroidOS_Basebridge_AC_2147796552_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:AndroidOS/Basebridge.AC"
        threat_id = "2147796552"
        type = "Backdoor"
        platform = "AndroidOS: Android operating system"
        family = "Basebridge"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "/a_BServer3" ascii //weight: 2
        $x_2_2 = "Lcom/sec/android/bridge/BridgeProvider" ascii //weight: 2
        $x_2_3 = "_sms_screen_finish_body_charge" ascii //weight: 2
        $x_2_4 = "jk_beSendSmsBack" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


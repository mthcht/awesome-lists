rule Trojan_AndroidOS_SmsHider_A_2147646888_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:AndroidOS/SmsHider.A"
        threat_id = "2147646888"
        type = "Trojan"
        platform = "AndroidOS: Android operating system"
        family = "SmsHider"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {78 6d 73 74 73 76 2e 63 6f 6d 2f (4e 6f 74 69|55 70 64 61) 2f}  //weight: 1, accuracy: Low
        $x_1_2 = "j.SMSHider.MainService" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_AndroidOS_SmsHider_B_2147658161_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:AndroidOS/SmsHider.B"
        threat_id = "2147658161"
        type = "Trojan"
        platform = "AndroidOS: Android operating system"
        family = "SmsHider"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {73 76 72 2e 6d 6f 73 69 6a 69 65 2e 63 6f 6d 2f (4e 6f 74 69|46 6f 72 65 75 6e) 2f}  //weight: 2, accuracy: Low
        $x_1_2 = "hider.AppInstall" ascii //weight: 1
        $x_1_3 = "network is not work!" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}


rule Trojan_AndroidOS_Feejar_A_2147836799_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:AndroidOS/Feejar.A!MTB"
        threat_id = "2147836799"
        type = "Trojan"
        platform = "AndroidOS: Android operating system"
        family = "Feejar"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_4_1 = "mode_for_sms_intercept" ascii //weight: 4
        $x_2_2 = {63 6f 6d 2f 63 [0-21] 2f 75 74 69 6c 2f 4e 65 74 77 6f 72 6b 53 74 61 74 65 52 65 63 65 69 76 65 72}  //weight: 2, accuracy: Low
        $x_1_3 = "m_smsservice" ascii //weight: 1
        $x_1_4 = "ritosmsfeepage" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_4_*) and 2 of ($x_1_*))) or
            ((1 of ($x_4_*) and 1 of ($x_2_*))) or
            (all of ($x*))
        )
}


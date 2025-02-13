rule Trojan_AndroidOS_Smspay_A_2147842836_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:AndroidOS/Smspay.A"
        threat_id = "2147842836"
        type = "Trojan"
        platform = "AndroidOS: Android operating system"
        family = "Smspay"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "GLO_APP_CHAN" ascii //weight: 1
        $x_1_2 = "STATUS_INT_PAYMENT_TERMS_ACCEPTED" ascii //weight: 1
        $x_1_3 = "bXRydXNzLnZlbmlzby5jb20vYXBpL210cnVzcy5kbw==" ascii //weight: 1
        $x_1_4 = "isSMSPaymentSuccessfulBSO" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_AndroidOS_Smspay_E_2147915738_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:AndroidOS/Smspay.E"
        threat_id = "2147915738"
        type = "Trojan"
        platform = "AndroidOS: Android operating system"
        family = "Smspay"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Well I can't do anything untill you permit me" ascii //weight: 1
        $x_1_2 = "Thank you for permission!" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


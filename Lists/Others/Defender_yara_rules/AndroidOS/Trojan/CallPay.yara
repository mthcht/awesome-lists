rule Trojan_AndroidOS_CallPay_A_2147832432_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:AndroidOS/CallPay.A!MTB"
        threat_id = "2147832432"
        type = "Trojan"
        platform = "AndroidOS: Android operating system"
        family = "CallPay"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {61 70 70 73 2f [0-19] 2f 64 61 74 61 2f 67 65 6f 69 70 2e 70 68 70}  //weight: 1, accuracy: Low
        $x_1_2 = {61 70 70 73 2f [0-19] 2f 64 61 74 61 2f 67 65 74 46 69 6e 67 65 72 70 72 69 6e 74 49 6e 66 6f 2e 70 68 70}  //weight: 1, accuracy: Low
        $x_1_3 = "public/notification/subscribe?country" ascii //weight: 1
        $x_1_4 = "app_sms_request_get_number.php" ascii //weight: 1
        $x_1_5 = "moboporn/data/device_admin.php" ascii //weight: 1
        $x_1_6 = "BestGames/index.php" ascii //weight: 1
        $x_1_7 = "hotappsxx" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (4 of ($x*))
}


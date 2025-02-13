rule Trojan_AndroidOS_ShastroSms_A_2147648553_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:AndroidOS/ShastroSms.A"
        threat_id = "2147648553"
        type = "Trojan"
        platform = "AndroidOS: Android operating system"
        family = "ShastroSms"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "ycya.db" ascii //weight: 1
        $x_1_2 = "pay_astro_shapy" ascii //weight: 1
        $x_1_3 = "sendYcya" ascii //weight: 1
        $x_1_4 = "val$payname" ascii //weight: 1
        $x_1_5 = "ta_astro" ascii //weight: 1
        $x_1_6 = "goneIfFail" ascii //weight: 1
        $x_1_7 = "CountUserFlag.db" ascii //weight: 1
        $x_1_8 = "api.go108.cn/client/trace/pay/Client:" ascii //weight: 1
        $x_1_9 = "astro/cin.jsp?c=aqll" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (4 of ($x*))
}


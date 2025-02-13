rule Trojan_AndroidOS_CipaSpy_A_2147851299_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:AndroidOS/CipaSpy.A!MTB"
        threat_id = "2147851299"
        type = "Trojan"
        platform = "AndroidOS: Android operating system"
        family = "CipaSpy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "9"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "apyBankData" ascii //weight: 1
        $x_1_2 = "requestMobileMsg" ascii //weight: 1
        $x_1_3 = "getXfWithHoldingBankCode" ascii //weight: 1
        $x_1_4 = "getAllBankCode_URL" ascii //weight: 1
        $x_5_5 = {7a 69 66 75 2f 70 61 79 6d 65 6e 74 2f [0-21] 2f 7a 69 66 75}  //weight: 5, accuracy: Low
        $x_1_6 = "saveMessageRecord" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_5_*) and 4 of ($x_1_*))) or
            (all of ($x*))
        )
}


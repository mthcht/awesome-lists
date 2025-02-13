rule Trojan_AndroidOS_SMSer_C_2147679337_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:AndroidOS/SMSer.C"
        threat_id = "2147679337"
        type = "Trojan"
        platform = "AndroidOS: Android operating system"
        family = "SMSer"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "15"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {70 72 69 6e 74 54 69 6d 65 73 00 2b 3d 3d 3d 3d 3d 3d 3d 3d 3d 3d 3d 3d 3d 3d 3d 3d 3d 3d 54 49 4d 45 53 3d}  //weight: 1, accuracy: High
        $x_5_2 = "block_numbers" ascii //weight: 5
        $x_2_3 = {61 63 74 76 69 74 79 43 6c 61 73 73 00}  //weight: 2, accuracy: High
        $x_5_4 = "net/URLConnection;" ascii //weight: 5
        $x_2_5 = {67 65 74 49 6d 65 69 00}  //weight: 2, accuracy: High
        $x_2_6 = {67 65 74 50 68 6f 6e 65 00}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_5_*) and 2 of ($x_2_*) and 1 of ($x_1_*))) or
            ((2 of ($x_5_*) and 3 of ($x_2_*))) or
            (all of ($x*))
        )
}

rule Trojan_AndroidOS_SMSer_A_2147744867_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:AndroidOS/SMSer.A!MTB"
        threat_id = "2147744867"
        type = "Trojan"
        platform = "AndroidOS: Android operating system"
        family = "SMSer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "palmfunplay.cn" ascii //weight: 1
        $x_1_2 = "/fplay_arthc" ascii //weight: 1
        $x_1_3 = "isSMSSendSucceed" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


rule PWS_AndroidOS_Coolware_A_2147826152_0
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:AndroidOS/Coolware.A"
        threat_id = "2147826152"
        type = "PWS"
        platform = "AndroidOS: Android operating system"
        family = "Coolware"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Lcom/spcbeauty/camapp" ascii //weight: 1
        $x_1_2 = "BASE_URL" ascii //weight: 1
        $x_1_3 = "getBASE_URL" ascii //weight: 1
        $x_1_4 = "toSlimming" ascii //weight: 1
        $x_1_5 = "Lcom/alibaba/android/arouter/facade/Postcard" ascii //weight: 1
        $x_1_6 = "toCartoon" ascii //weight: 1
        $x_1_7 = "jumpWith" ascii //weight: 1
        $x_1_8 = "/app/slimming/" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule PWS_AndroidOS_Coolware_B_2147826153_0
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:AndroidOS/Coolware.B"
        threat_id = "2147826153"
        type = "PWS"
        platform = "AndroidOS: Android operating system"
        family = "Coolware"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "11"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "toAesDecrypt" ascii //weight: 1
        $x_1_2 = "toAesEncrypt" ascii //weight: 1
        $x_1_3 = "Lqqq/www/eee/ev/B" ascii //weight: 1
        $x_4_4 = "helloWorldIamBoy" ascii //weight: 4
        $x_4_5 = "IamBoyhelloworld" ascii //weight: 4
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


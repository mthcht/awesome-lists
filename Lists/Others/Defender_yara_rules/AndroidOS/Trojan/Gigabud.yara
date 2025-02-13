rule Trojan_AndroidOS_Gigabud_C_2147839575_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:AndroidOS/Gigabud.C"
        threat_id = "2147839575"
        type = "Trojan"
        platform = "AndroidOS: Android operating system"
        family = "Gigabud"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "writeVideoUrl" ascii //weight: 1
        $x_1_2 = "x/user-bank-pwd" ascii //weight: 1
        $x_1_3 = "startUploadScreenRecord" ascii //weight: 1
        $x_1_4 = "isHaveAccessibility" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_AndroidOS_Gigabud_D_2147841712_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:AndroidOS/Gigabud.D"
        threat_id = "2147841712"
        type = "Trojan"
        platform = "AndroidOS: Android operating system"
        family = "Gigabud"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "Lvirbox/StubApp" ascii //weight: 2
        $x_1_2 = "l0df2aae4$jntm" ascii //weight: 1
        $x_1_3 = "I676efb5b_03" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Trojan_AndroidOS_Gigabud_D_2147841712_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:AndroidOS/Gigabud.D"
        threat_id = "2147841712"
        type = "Trojan"
        platform = "AndroidOS: Android operating system"
        family = "Gigabud"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "MESSAGE_START_UPLOAD" ascii //weight: 2
        $x_2_2 = "startRecordAndUpload" ascii //weight: 2
        $x_2_3 = "onScreenDataEncoded" ascii //weight: 2
        $x_2_4 = "whopenurl:" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_AndroidOS_Gigabud_A_2147842543_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:AndroidOS/Gigabud.A"
        threat_id = "2147842543"
        type = "Trojan"
        platform = "AndroidOS: Android operating system"
        family = "Gigabud"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "SettingSafePwdActivity" ascii //weight: 2
        $x_2_2 = "WaitCheckActivity" ascii //weight: 2
        $x_2_3 = "queryPermissionStatusAndStartNextQuery" ascii //weight: 2
        $x_2_4 = "isHaveSendMsg" ascii //weight: 2
        $x_2_5 = "controller/TouchAccessibilityService" ascii //weight: 2
        $x_2_6 = "ShowBankDF" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (5 of ($x*))
}


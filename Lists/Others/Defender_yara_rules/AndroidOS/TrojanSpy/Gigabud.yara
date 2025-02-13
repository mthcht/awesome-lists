rule TrojanSpy_AndroidOS_Gigabud_K_2147850672_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:AndroidOS/Gigabud.K!MTB"
        threat_id = "2147850672"
        type = "TrojanSpy"
        platform = "AndroidOS: Android operating system"
        family = "Gigabud"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {21 32 35 21 0c 00 48 02 03 01 df 02 02 69 8d 22 4f 02 03 01 d8 01 01 01 28 f4}  //weight: 1, accuracy: High
        $x_1_2 = "BankCardInfo" ascii //weight: 1
        $x_1_3 = "writeVideoUrl" ascii //weight: 1
        $x_1_4 = "x/user-bank-pwd" ascii //weight: 1
        $x_1_5 = "execute command" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

rule TrojanSpy_AndroidOS_Gigabud_A_2147901527_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:AndroidOS/Gigabud.A!MTB"
        threat_id = "2147901527"
        type = "TrojanSpy"
        platform = "AndroidOS: Android operating system"
        family = "Gigabud"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "BankCardInfo(bankCardNum=" ascii //weight: 1
        $x_1_2 = "com/yk/accessibility" ascii //weight: 1
        $x_1_3 = "getBankCardNum" ascii //weight: 1
        $x_1_4 = "TouchAccessibilityService" ascii //weight: 1
        $x_1_5 = "isXfPermissionOpen" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


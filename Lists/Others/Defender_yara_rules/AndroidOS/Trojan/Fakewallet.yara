rule Trojan_AndroidOS_FakeWallet_B_2147826773_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:AndroidOS/FakeWallet.B!MTB"
        threat_id = "2147826773"
        type = "Trojan"
        platform = "AndroidOS: Android operating system"
        family = "FakeWallet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "com/tokenbank/activity/splash" ascii //weight: 1
        $x_1_2 = "uploadpwd_run" ascii //weight: 1
        $x_1_3 = "uploadMnemonic" ascii //weight: 1
        $x_1_4 = "uploadUname_Pwd" ascii //weight: 1
        $x_1_5 = "uploadMsg" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


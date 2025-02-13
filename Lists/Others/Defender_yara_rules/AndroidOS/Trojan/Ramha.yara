rule Trojan_AndroidOS_Ramha_A_2147839291_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:AndroidOS/Ramha.A!MTB"
        threat_id = "2147839291"
        type = "Trojan"
        platform = "AndroidOS: Android operating system"
        family = "Ramha"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "tools/app/downloaders" ascii //weight: 1
        $x_1_2 = "VerifyHamrahAvalOtpActivity" ascii //weight: 1
        $x_1_3 = "/fanap.rtellservers.com/api/verify_otp_request_keyboard/" ascii //weight: 1
        $x_1_4 = "ToolsSmsReceiver" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


rule TrojanSpy_AndroidOS_SpyLoan_A_2147814198_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:AndroidOS/SpyLoan.A!MTB"
        threat_id = "2147814198"
        type = "TrojanSpy"
        platform = "AndroidOS: Android operating system"
        family = "SpyLoan"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "gather_sms" ascii //weight: 1
        $x_1_2 = "gather_call" ascii //weight: 1
        $x_1_3 = "callhistoryStatus" ascii //weight: 1
        $x_1_4 = "mobileInfoData" ascii //weight: 1
        $x_1_5 = "FakeX509TrustManager" ascii //weight: 1
        $x_1_6 = "com/ppdai/loan/common/gather/GatherMgr" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanSpy_AndroidOS_SpyLoan_C_2147903256_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:AndroidOS/SpyLoan.C!MTB"
        threat_id = "2147903256"
        type = "TrojanSpy"
        platform = "AndroidOS: Android operating system"
        family = "SpyLoan"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "tb_account_selected" ascii //weight: 1
        $x_1_2 = "requestPermissionAndUploadDeviceInfo" ascii //weight: 1
        $x_1_3 = "CashSmsData" ascii //weight: 1
        $x_1_4 = "ConfirmLoanAdapter" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


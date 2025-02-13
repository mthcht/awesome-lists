rule VirTool_MSIL_Shrewd_A_2147764974_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:MSIL/Shrewd.A!MTB"
        threat_id = "2147764974"
        type = "VirTool"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Shrewd"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "userChromiumLoginDataPath" ascii //weight: 1
        $x_1_2 = "chromiumBasePath" ascii //weight: 1
        $x_1_3 = "userChromiumCookiesPath" ascii //weight: 1
        $x_1_4 = "userChromiumBookmarksPathEnd" ascii //weight: 1
        $x_1_5 = "userChromiumHistoryPath" ascii //weight: 1
        $x_1_6 = "ChromiumCredentialManager" ascii //weight: 1
        $x_1_7 = "ChromiumUtils" ascii //weight: 1
        $x_1_8 = "DPAPIChromeAlgKeyFromRaw" ascii //weight: 1
        $x_1_9 = "DPAPIChromiumAlgFromKeyRaw" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (8 of ($x*))
}


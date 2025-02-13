rule PWS_MSIL_DarkStealer_AD_2147764924_0
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:MSIL/DarkStealer.AD!MTB"
        threat_id = "2147764924"
        type = "PWS"
        platform = "MSIL: .NET intermediate language scripts"
        family = "DarkStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "credential" wide //weight: 1
        $x_1_2 = "https://api.telegram.org/bot%telegramapi%/" wide //weight: 1
        $x_1_3 = "%chatid%" wide //weight: 1
        $x_1_4 = "logins" wide //weight: 1
        $x_1_5 = "HTTP/1.1" wide //weight: 1
        $x_1_6 = "onion" wide //weight: 1
        $x_1_7 = "torproject" wide //weight: 1
        $x_1_8 = "sha512" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule PWS_MSIL_DarkStealer_AD_2147764924_1
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:MSIL/DarkStealer.AD!MTB"
        threat_id = "2147764924"
        type = "PWS"
        platform = "MSIL: .NET intermediate language scripts"
        family = "DarkStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "213"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "get_bindingConfigurationUID" ascii //weight: 1
        $x_1_2 = "set_bindingConfigurationUID" ascii //weight: 1
        $x_1_3 = "get_URL" ascii //weight: 1
        $x_1_4 = "set_URL" ascii //weight: 1
        $x_1_5 = "get_sSL" ascii //weight: 1
        $x_1_6 = "set_sSL" ascii //weight: 1
        $x_1_7 = "get_LastAccessed" ascii //weight: 1
        $x_1_8 = "set_LastAccessed" ascii //weight: 1
        $x_1_9 = "get_Clipboard" ascii //weight: 1
        $x_1_10 = "get_Keyboard" ascii //weight: 1
        $x_1_11 = "get_Password" ascii //weight: 1
        $x_1_12 = "set_Password" ascii //weight: 1
        $x_1_13 = "get_useSeparateFolderTree" ascii //weight: 1
        $x_1_14 = "set_useSeparateFolderTree" ascii //weight: 1
        $x_1_15 = "SendMessage" ascii //weight: 1
        $x_1_16 = "MailMessage" ascii //weight: 1
        $x_1_17 = "get_securityProfile" ascii //weight: 1
        $x_1_18 = "set_securityProfile" ascii //weight: 1
        $x_1_19 = "get_Credentials" ascii //weight: 1
        $x_1_20 = "set_Credentials" ascii //weight: 1
        $x_1_21 = "get_DefaultCredentials" ascii //weight: 1
        $x_1_22 = "set_UseDefaultCredentials" ascii //weight: 1
        $x_1_23 = "get_InternalServerPort" ascii //weight: 1
        $x_1_24 = "set_InternalServerPort" ascii //weight: 1
        $x_1_25 = "get_GuidMasterKey" ascii //weight: 1
        $x_1_26 = "set_GuidMasterKey" ascii //weight: 1
        $x_50_27 = "SetWindowsHookEx" ascii //weight: 50
        $x_50_28 = "ICredentialsByHost" ascii //weight: 50
        $x_50_29 = "get_TotalPhysicalMemory" ascii //weight: 50
        $x_50_30 = "set_CreateNoWindow" ascii //weight: 50
    condition:
        (filesize < 20MB) and
        (
            ((4 of ($x_50_*) and 13 of ($x_1_*))) or
            (all of ($x*))
        )
}


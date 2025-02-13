rule PWS_MSIL_MassLogger_2147770499_0
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:MSIL/MassLogger!MTB"
        threat_id = "2147770499"
        type = "PWS"
        platform = "MSIL: .NET intermediate language scripts"
        family = "MassLogger"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "21"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "GetCredentials" ascii //weight: 1
        $x_1_2 = "_formSubmitURL" ascii //weight: 1
        $x_1_3 = "_AdapterRAM" ascii //weight: 1
        $x_1_4 = "_GrabVPN" ascii //weight: 1
        $x_1_5 = "_NordVPN" ascii //weight: 1
        $x_1_6 = "_OpenVPN" ascii //weight: 1
        $x_1_7 = "_ProtonVPN" ascii //weight: 1
        $x_1_8 = "RM_PROCESS_INFO" ascii //weight: 1
        $x_1_9 = "_BlacklistedIP" ascii //weight: 1
        $x_1_10 = "_GrabFTP" ascii //weight: 1
        $x_1_11 = "RM_UNIQUE_PROCESS" ascii //weight: 1
        $x_1_12 = "_timePasswordChanged" ascii //weight: 1
        $x_1_13 = "_IsProcessElevated" ascii //weight: 1
        $x_1_14 = "ExpirationYear" ascii //weight: 1
        $x_1_15 = "ExpirationMonth" ascii //weight: 1
        $x_1_16 = "CardNumber" ascii //weight: 1
        $x_1_17 = "Holder" ascii //weight: 1
        $x_1_18 = "CreditCards" ascii //weight: 1
        $x_1_19 = "GrabWallets" ascii //weight: 1
        $x_1_20 = "GrabScreenshot" ascii //weight: 1
        $x_1_21 = "DetectCreditCardType" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule PWS_MSIL_MassLogger_AD_2147795231_0
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:MSIL/MassLogger.AD!!MassLogger.AD!MTB"
        threat_id = "2147795231"
        type = "PWS"
        platform = "MSIL: .NET intermediate language scripts"
        family = "MassLogger"
        severity = "Critical"
        info = "MassLogger: an internal category used to refer to some threats"
        info = "AD: an internal category used to refer to some threats"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_ARHSTR_EXT"
        threshold = "21"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "GetCredentials" ascii //weight: 1
        $x_1_2 = "_formSubmitURL" ascii //weight: 1
        $x_1_3 = "_AdapterRAM" ascii //weight: 1
        $x_1_4 = "_GrabVPN" ascii //weight: 1
        $x_1_5 = "_NordVPN" ascii //weight: 1
        $x_1_6 = "_OpenVPN" ascii //weight: 1
        $x_1_7 = "_ProtonVPN" ascii //weight: 1
        $x_1_8 = "RM_PROCESS_INFO" ascii //weight: 1
        $x_1_9 = "_BlacklistedIP" ascii //weight: 1
        $x_1_10 = "_GrabFTP" ascii //weight: 1
        $x_1_11 = "RM_UNIQUE_PROCESS" ascii //weight: 1
        $x_1_12 = "_timePasswordChanged" ascii //weight: 1
        $x_1_13 = "_IsProcessElevated" ascii //weight: 1
        $x_1_14 = "ExpirationYear" ascii //weight: 1
        $x_1_15 = "ExpirationMonth" ascii //weight: 1
        $x_1_16 = "CardNumber" ascii //weight: 1
        $x_1_17 = "Holder" ascii //weight: 1
        $x_1_18 = "CreditCards" ascii //weight: 1
        $x_1_19 = "GrabWallets" ascii //weight: 1
        $x_1_20 = "GrabScreenshot" ascii //weight: 1
        $x_1_21 = "DetectCreditCardType" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


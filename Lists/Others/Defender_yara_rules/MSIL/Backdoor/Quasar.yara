rule Backdoor_MSIL_Quasar_GG_2147772079_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:MSIL/Quasar.GG!MTB"
        threat_id = "2147772079"
        type = "Backdoor"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Quasar"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "16"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "Quasar.Client." ascii //weight: 10
        $x_1_2 = "Payload" ascii //weight: 1
        $x_1_3 = "MouseKeyHook" ascii //weight: 1
        $x_1_4 = "login" ascii //weight: 1
        $x_1_5 = "password" ascii //weight: 1
        $x_1_6 = "PK11SDR_Decrypt" ascii //weight: 1
        $x_1_7 = "WinSCPDecrypt" ascii //weight: 1
        $x_1_8 = "EncryptedPassword" ascii //weight: 1
        $x_1_9 = "Shutdown" ascii //weight: 1
        $x_1_10 = "ReverseProxy" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_10_*) and 6 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Backdoor_MSIL_Quasar_GG_2147772079_1
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:MSIL/Quasar.GG!MTB"
        threat_id = "2147772079"
        type = "Backdoor"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Quasar"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "QuasarClient" ascii //weight: 1
        $x_1_2 = "payload" ascii //weight: 1
        $x_1_3 = "xClient.Core" ascii //weight: 1
        $x_1_4 = "Botkiller" ascii //weight: 1
        $x_1_5 = "keylogger" ascii //weight: 1
        $x_1_6 = "injector" ascii //weight: 1
        $x_1_7 = "DoWebcamStop" ascii //weight: 1
        $x_1_8 = "DoProcessKill" ascii //weight: 1
        $x_1_9 = "DoClientUpdate" ascii //weight: 1
        $x_1_10 = "DoClientRestoreDel" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (6 of ($x*))
}

rule Backdoor_MSIL_Quasar_GG_2147772079_2
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:MSIL/Quasar.GG!MTB"
        threat_id = "2147772079"
        type = "Backdoor"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Quasar"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "9"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Cookie" ascii //weight: 1
        $x_1_2 = "ColdWallets" ascii //weight: 1
        $x_1_3 = "FtpManagers" ascii //weight: 1
        $x_1_4 = "RdpManagers" ascii //weight: 1
        $x_1_5 = "SERVER_CREDENTIAL" ascii //weight: 1
        $x_1_6 = "BrowserCreditCard" ascii //weight: 1
        $x_1_7 = "Payload" ascii //weight: 1
        $x_1_8 = "AntiVM" ascii //weight: 1
        $x_1_9 = "ANTIVIRUS" ascii //weight: 1
        $x_1_10 = "FIREWALL" ascii //weight: 1
        $x_1_11 = "ANTISPYWARE" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (9 of ($x*))
}

rule Backdoor_MSIL_Quasar_GG_2147772079_3
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:MSIL/Quasar.GG!MTB"
        threat_id = "2147772079"
        type = "Backdoor"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Quasar"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "26"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "QuasarClient" ascii //weight: 10
        $x_10_2 = "payload" ascii //weight: 10
        $x_1_3 = "ENABLELOGGER" ascii //weight: 1
        $x_1_4 = "HIDELOGDIRECTORY" ascii //weight: 1
        $x_1_5 = "DoMouseMove" ascii //weight: 1
        $x_1_6 = "DoPathDelete" ascii //weight: 1
        $x_1_7 = "DoPathRename" ascii //weight: 1
        $x_1_8 = "DoGenerateSeed" ascii //weight: 1
        $x_1_9 = "DoCopyWithNewPassword" ascii //weight: 1
        $x_1_10 = "DoShellExecute" ascii //weight: 1
        $x_1_11 = "DoParseSecretKeyFromSExpr" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_10_*) and 6 of ($x_1_*))) or
            (all of ($x*))
        )
}


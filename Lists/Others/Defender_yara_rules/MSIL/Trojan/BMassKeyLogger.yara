rule Trojan_MSIL_BMassKeyLogger_2147759964_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/BMassKeyLogger!MTB"
        threat_id = "2147759964"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "BMassKeyLogger"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "40"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "FtpEnable" ascii //weight: 1
        $x_1_2 = "FtpHost" ascii //weight: 1
        $x_1_3 = "FtpUser" ascii //weight: 1
        $x_1_4 = "FtpPass" ascii //weight: 1
        $x_1_5 = "FtpPort" ascii //weight: 1
        $x_1_6 = "EmailEnable" ascii //weight: 1
        $x_1_7 = "EmailAddress" ascii //weight: 1
        $x_1_8 = "EmailSendTo" ascii //weight: 1
        $x_1_9 = "EmailPass" ascii //weight: 1
        $x_1_10 = "EmailPort" ascii //weight: 1
        $x_1_11 = "EmailSsl" ascii //weight: 1
        $x_1_12 = "EmailClient" ascii //weight: 1
        $x_1_13 = "PanelEnable" ascii //weight: 1
        $x_1_14 = "PanelHost" ascii //weight: 1
        $x_1_15 = "ExitAfterDelivery" ascii //weight: 1
        $x_1_16 = "SelfDestruct" ascii //weight: 1
        $x_1_17 = "EnableMutex" ascii //weight: 1
        $x_1_18 = "EnableAntiSandboxie" ascii //weight: 1
        $x_1_19 = "EnableAntiVMware" ascii //weight: 1
        $x_1_20 = "EnableAntiDebugger" ascii //weight: 1
        $x_1_21 = "EnableWDExclusion" ascii //weight: 1
        $x_1_22 = "EnableSearchAndUpload" ascii //weight: 1
        $x_1_23 = "EnableSpreadUsb" ascii //weight: 1
        $x_1_24 = "EnableKeylogger" ascii //weight: 1
        $x_1_25 = "EnableBrowserRecovery" ascii //weight: 1
        $x_1_26 = "EnableScreenshot" ascii //weight: 1
        $x_1_27 = "EnableForceUac" ascii //weight: 1
        $x_1_28 = "EnableBotKiller" ascii //weight: 1
        $x_1_29 = "EnableDeleteZoneIdentifier" ascii //weight: 1
        $x_1_30 = "EnableMemoryScan" ascii //weight: 1
        $x_1_31 = "EnableAntiHoneypot" ascii //weight: 1
        $x_1_32 = "EnableOnlySendWhenPassword" ascii //weight: 1
        $x_1_33 = "ExectionDelay" ascii //weight: 1
        $x_1_34 = "SendingInterval" ascii //weight: 1
        $x_1_35 = "EnableDownloader" ascii //weight: 1
        $x_1_36 = "DownloaderUrl" ascii //weight: 1
        $x_1_37 = "DownloaderFilename" ascii //weight: 1
        $x_1_38 = "DownloaderOnce" ascii //weight: 1
        $x_1_39 = "EnableBinder" ascii //weight: 1
        $x_1_40 = "BinderBytes" ascii //weight: 1
        $x_1_41 = "BinderName" ascii //weight: 1
        $x_1_42 = "BinderOnce" ascii //weight: 1
        $x_1_43 = "EnableInstall" ascii //weight: 1
        $x_1_44 = "InstallFolder" ascii //weight: 1
        $x_1_45 = "InstallSecondFolder" ascii //weight: 1
        $x_1_46 = "InstallFile" ascii //weight: 1
        $x_1_47 = "SearchAndUploadExtensions" ascii //weight: 1
        $x_1_48 = "SearchAndUploadSizeLimit" ascii //weight: 1
        $x_1_49 = "SearchAndUploadZipSize" ascii //weight: 1
        $x_1_50 = "EnableWindowSearcher" ascii //weight: 1
        $x_1_51 = "WindowSearcherKeywords" ascii //weight: 1
        $x_1_52 = "MainDirectory" ascii //weight: 1
        $x_1_53 = "SafeThread" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (40 of ($x*))
}


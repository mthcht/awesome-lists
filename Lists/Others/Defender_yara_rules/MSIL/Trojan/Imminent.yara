rule Trojan_MSIL_Imminent_A_2147729958_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Imminent.A!MTB"
        threat_id = "2147729958"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Imminent"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "15"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "PluginManager Ready" ascii //weight: 1
        $x_1_2 = "PluginPacketHandler Ready" ascii //weight: 1
        $x_1_3 = "Chat Ready" ascii //weight: 1
        $x_1_4 = "Remote Desktop Ready" ascii //weight: 1
        $x_1_5 = "KeyHook Ready" ascii //weight: 1
        $x_1_6 = "KeyManager Ready" ascii //weight: 1
        $x_1_7 = "Microphone Ready" ascii //weight: 1
        $x_1_8 = "ReverseProxy Ready" ascii //weight: 1
        $x_1_9 = "RDP Ready" ascii //weight: 1
        $x_1_10 = "RemoteWebcam Ready" ascii //weight: 1
        $x_1_11 = "InstallerForm Ready" ascii //weight: 1
        $x_1_12 = "ClipboardManager Ready" ascii //weight: 1
        $x_1_13 = "CommandPrompt Ready" ascii //weight: 1
        $x_1_14 = "ExecuteUpdateManager Ready" ascii //weight: 1
        $x_1_15 = "FileManager Ready" ascii //weight: 1
        $x_1_16 = "FileTransfer Ready" ascii //weight: 1
        $x_1_17 = "MessageBox Ready" ascii //weight: 1
        $x_1_18 = "ProcessManager Ready" ascii //weight: 1
        $x_1_19 = "RegistryManager Ready" ascii //weight: 1
        $x_1_20 = "ScriptingManager Ready" ascii //weight: 1
        $x_1_21 = "SimpleTransfer Ready" ascii //weight: 1
        $x_1_22 = "StartupManager Ready" ascii //weight: 1
        $x_1_23 = "TCPConnections Ready" ascii //weight: 1
        $x_1_24 = "WindowManager Ready" ascii //weight: 1
        $x_1_25 = "PasswordRecovery Ready" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (15 of ($x*))
}

rule Trojan_MSIL_Imminent_B_2147731641_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Imminent.B"
        threat_id = "2147731641"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Imminent"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Please-contact-abuse@imminentmethods.net" ascii //weight: 1
        $x_1_2 = "if-this-assembly-was-found-being-used-maliciously" ascii //weight: 1
        $x_1_3 = "This-file-was-built-using-Invisible-Mode" ascii //weight: 1
        $x_1_4 = "Imminent-Monitor-Client-Watermark" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


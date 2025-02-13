rule Trojan_Win32_Bancos_B_2147647197_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Bancos.B"
        threat_id = "2147647197"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Bancos"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Falha ao carregar video" wide //weight: 1
        $x_1_2 = "five5\\cdaf" wide //weight: 1
        $x_1_3 = "MonitoraEnvioDeDados" ascii //weight: 1
        $x_1_4 = "EnviaMailCop" ascii //weight: 1
        $x_1_5 = "BaixarArquivos" ascii //weight: 1
        $x_1_6 = "ContaminaAlt" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (5 of ($x*))
}

rule Trojan_Win32_Bancos_A_2147819812_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Bancos.A!MTB"
        threat_id = "2147819812"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Bancos"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "23"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "RegCreateKey" ascii //weight: 1
        $x_1_2 = "RegDeleteValue" ascii //weight: 1
        $x_1_3 = "RegOpenKey" ascii //weight: 1
        $x_1_4 = "RegQueryValue" ascii //weight: 1
        $x_1_5 = "RegSetValue" ascii //weight: 1
        $x_1_6 = "grab=" wide //weight: 1
        $x_1_7 = "skype.exe" wide //weight: 1
        $x_1_8 = "taskmgr.exe" wide //weight: 1
        $x_1_9 = "explorer.exe" wide //weight: 1
        $x_1_10 = "msnmsgr.exe" wide //weight: 1
        $x_1_11 = "YahooMessenger.exe" wide //weight: 1
        $x_1_12 = "AOL.exe" wide //weight: 1
        $x_1_13 = "software\\microsoft\\windows\\currentversion\\policies\\system" wide //weight: 1
        $x_1_14 = "DisableTaskMgr" wide //weight: 1
        $x_1_15 = "software\\microsoft\\windows\\currentversion\\policies\\Explorer" wide //weight: 1
        $x_1_16 = "DisableLockWorkstation" wide //weight: 1
        $x_1_17 = "DisableChangePassword" wide //weight: 1
        $x_1_18 = "Software\\Microsoft\\Windows NT\\CurrentVersion\\SystemRestore" wide //weight: 1
        $x_1_19 = "Software\\Policies\\Microsoft\\Windows\\System" wide //weight: 1
        $x_1_20 = "DisableCMD" wide //weight: 1
        $x_1_21 = "DisableRegistryTools" wide //weight: 1
        $x_1_22 = "ShutdownPrivilege" wide //weight: 1
        $x_1_23 = "Software\\Microsoft\\Windows\\CurrentVersion\\RunOnce" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


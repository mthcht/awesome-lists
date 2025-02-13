rule Trojan_MSIL_DynamicStealer_CT_2147843348_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/DynamicStealer.CT!MTB"
        threat_id = "2147843348"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "DynamicStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "12"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "get_MachineName" ascii //weight: 1
        $x_1_2 = "get_UserName" ascii //weight: 1
        $x_1_3 = "GetPasswords" ascii //weight: 1
        $x_1_4 = "DLL/PasswordStealer.dll" wide //weight: 1
        $x_1_5 = "schtasks.exe" wide //weight: 1
        $x_1_6 = "/create /f /sc ONLOGON /RL HIGHEST /tn" wide //weight: 1
        $x_1_7 = "/C choice /C Y /N /D Y /T 3 & Del" wide //weight: 1
        $x_1_8 = "SELECT * FROM Win32_BIOS" wide //weight: 1
        $x_1_9 = "SELECT * FROM Win32_Processor" wide //weight: 1
        $x_1_10 = "SELECT * FROM Win32_ComputerSystem" wide //weight: 1
        $x_1_11 = "SELECT * FROM Win32_OperatingSystem" wide //weight: 1
        $x_1_12 = "PasswordStealer" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


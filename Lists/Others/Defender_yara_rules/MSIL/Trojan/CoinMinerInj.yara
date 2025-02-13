rule Trojan_MSIL_CoinMinerInj_2147784686_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/CoinMinerInj!MTB"
        threat_id = "2147784686"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "CoinMinerInj"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "\\root\\cimv2" wide //weight: 1
        $x_1_2 = "Select CommandLine from Win32_Process where Name='{0}'" wide //weight: 1
        $x_1_3 = "CommandLine" wide //weight: 1
        $x_1_4 = "--cinit-find-" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_CoinMinerInj_2147784686_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/CoinMinerInj!MTB"
        threat_id = "2147784686"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "CoinMinerInj"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "<PrivateImplementationDetails>{" ascii //weight: 1
        $x_1_2 = "set_CreateNoWindow" ascii //weight: 1
        $x_1_3 = "$$method0x6" ascii //weight: 1
        $x_1_4 = "/c schtasks /create /f /sc onlogon /rl highest /tn \"" wide //weight: 1
        $x_1_5 = "Select CommandLine from Win32_Process where Name='{0}'" wide //weight: 1
        $x_1_6 = "\\root\\cimv2" wide //weight: 1
        $x_1_7 = "CommandLine" wide //weight: 1
        $x_1_8 = "--donate-l" wide //weight: 1
        $x_1_9 = "{%RANDOM%}" wide //weight: 1
        $x_1_10 = "{%COMPUTERNAME%}" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


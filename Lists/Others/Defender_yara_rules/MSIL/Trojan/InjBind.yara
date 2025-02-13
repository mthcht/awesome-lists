rule Trojan_MSIL_InjBind_2147763176_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/InjBind!MTB"
        threat_id = "2147763176"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "InjBind"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "9"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "VirtualAlloc" ascii //weight: 1
        $x_1_2 = "set_Arguments" ascii //weight: 1
        $x_1_3 = "set_UseShellExecute" ascii //weight: 1
        $x_1_4 = "set_RedirectStandardOutput" ascii //weight: 1
        $x_1_5 = "set_CreateNoWindow" ascii //weight: 1
        $x_1_6 = "\\Microsoft.NET\\Framework\\v4.0.30319\\RegAsm.exe" wide //weight: 1
        $x_1_7 = "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run" wide //weight: 1
        $x_1_8 = "#bind_sett#" wide //weight: 1
        $x_1_9 = "\\#bindname#.exe" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_InjBind_2147763176_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/InjBind!MTB"
        threat_id = "2147763176"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "InjBind"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "19"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "SET_THREAD_TOKEN" ascii //weight: 1
        $x_1_2 = "SET_INFORMATION" ascii //weight: 1
        $x_1_3 = "QUERY_INFORMATION" ascii //weight: 1
        $x_1_4 = "DIRECT_IMPERSONATION" ascii //weight: 1
        $x_1_5 = "THREAD_ALL_ACCESS" ascii //weight: 1
        $x_1_6 = "\\Microsoft.NET\\Framework\\v4.0.30319\\RegAsm.exe" wide //weight: 1
        $x_1_7 = "[InternetShortcut]" wide //weight: 1
        $x_1_8 = "URL=file:///" wide //weight: 1
        $x_1_9 = "schtasks.exe" wide //weight: 1
        $x_1_10 = "/create /sc MINUTE /tn" wide //weight: 1
        $x_1_11 = "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run" wide //weight: 1
        $x_1_12 = "#startup_method#" wide //weight: 1
        $x_1_13 = "#startup_name#" wide //weight: 1
        $x_1_14 = "#installation_method#" wide //weight: 1
        $x_1_15 = "#installation_name#" wide //weight: 1
        $x_1_16 = "#delay_sec#" wide //weight: 1
        $x_1_17 = "#bind_sett#" wide //weight: 1
        $x_1_18 = "Inject" wide //weight: 1
        $x_1_19 = "\\#bindname#.exe" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


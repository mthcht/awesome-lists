rule VirTool_MSIL_Luxod_A_2147692807_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:MSIL/Luxod.A"
        threat_id = "2147692807"
        type = "VirTool"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Luxod"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "AddToStartup" ascii //weight: 1
        $x_1_2 = "InjectionTarget" ascii //weight: 1
        $x_1_3 = "HasPersistence" ascii //weight: 1
        $x_1_4 = "MeltFile" ascii //weight: 1
        $x_1_5 = "EnableDownloader" ascii //weight: 1
        $x_1_6 = "BypassProactives" ascii //weight: 1
        $x_1_7 = "add \"HKCU\\Software\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon\" /f /v shell /t REG_SZ /d explorer.exe,\"" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (5 of ($x*))
}

rule VirTool_MSIL_Luxod_B_2147710455_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:MSIL/Luxod.B"
        threat_id = "2147710455"
        type = "VirTool"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Luxod"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {41 6e 74 69 73 00}  //weight: 1, accuracy: High
        $x_1_2 = {49 6e 6a 65 63 74 69 6f 6e 54 61 72 67 65 74 00}  //weight: 1, accuracy: High
        $x_1_3 = {44 69 73 61 62 6c 65 72 73 00}  //weight: 1, accuracy: High
        $x_1_4 = {4d 65 6c 74 46 69 6c 65 00}  //weight: 1, accuracy: High
        $x_1_5 = {45 6e 61 62 6c 65 53 74 61 72 74 75 70 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


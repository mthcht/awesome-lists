rule VirTool_MSIL_AsmInject_A_2147691110_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:MSIL/AsmInject.A"
        threat_id = "2147691110"
        type = "VirTool"
        platform = "MSIL: .NET intermediate language scripts"
        family = "AsmInject"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "101"
        strings_accuracy = "High"
    strings:
        $x_100_1 = "Loader, Version=1.0.0.0, Culture=neutral, PublicKeyToken=null" wide //weight: 100
        $x_1_2 = "|Self Inject|False|False|" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_MSIL_AsmInject_A_2147691110_1
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:MSIL/AsmInject.A"
        threat_id = "2147691110"
        type = "VirTool"
        platform = "MSIL: .NET intermediate language scripts"
        family = "AsmInject"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "100"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Loader, Version=1.0.0.0, Culture=neutral, PublicKeyToken=null" wide //weight: 1
        $x_1_2 = "|Self Inject|False|False|" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_MSIL_AsmInject_A_2147691110_2
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:MSIL/AsmInject.A"
        threat_id = "2147691110"
        type = "VirTool"
        platform = "MSIL: .NET intermediate language scripts"
        family = "AsmInject"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {7b 4c 00 6f 00 61 00 64 00 65 00 72 00 2c 00 20 00 56 00 65 00 72 00 73 00 69 00 6f 00 6e 00 3d 00 31 00 2e 00 30 00 2e 00 30 00 2e 00 30 00 2c 00 20 00 43 00 75 00 6c 00 74 00 75 00 72 00 65 00 3d 00 6e 00 65 00 75 00 74 00 72 00 61 00 6c 00 2c 00 20 00 50 00 75 00 62 00 6c 00 69 00 63 00 4b 00 65 00 79 00 54 00 6f 00 6b 00 65 00 6e 00 3d 00 6e 00 75 00 6c 00 6c 00}  //weight: 1, accuracy: High
        $x_1_2 = "InjectionLibrary" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_MSIL_AsmInject_B_2147691331_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:MSIL/AsmInject.B"
        threat_id = "2147691331"
        type = "VirTool"
        platform = "MSIL: .NET intermediate language scripts"
        family = "AsmInject"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "IsSandboxie" ascii //weight: 1
        $x_1_2 = "IsNormanSandbox" ascii //weight: 1
        $x_1_3 = "IsSunbeltSandbox" ascii //weight: 1
        $x_1_4 = "IsAnubisSandbox" ascii //weight: 1
        $x_1_5 = "IsCWSandbox" ascii //weight: 1
        $x_1_6 = "IsWireshark" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

rule VirTool_MSIL_AsmInject_C_2147692840_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:MSIL/AsmInject.C"
        threat_id = "2147692840"
        type = "VirTool"
        platform = "MSIL: .NET intermediate language scripts"
        family = "AsmInject"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {16 0a 2b 1f 02 06 8f ?? 00 00 01 25 71 00 00 00 01 03 06 03 8e 69 5d 91 61 d2 81 00 00 00 01 06 17 58 0a 06 02 8e 69 32 db 02 28 ?? 00 00 0a 6f ?? 00 00 0a 14 7e ?? 00 00 04 6f ?? 00 00 0a}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_MSIL_AsmInject_E_2147692848_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:MSIL/AsmInject.E"
        threat_id = "2147692848"
        type = "VirTool"
        platform = "MSIL: .NET intermediate language scripts"
        family = "AsmInject"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "100"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Coded for ParCrypter. Revision" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_MSIL_AsmInject_G_2147695605_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:MSIL/AsmInject.G"
        threat_id = "2147695605"
        type = "VirTool"
        platform = "MSIL: .NET intermediate language scripts"
        family = "AsmInject"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "100"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Dexter_crypt2.exe" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_MSIL_AsmInject_H_2147705944_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:MSIL/AsmInject.H"
        threat_id = "2147705944"
        type = "VirTool"
        platform = "MSIL: .NET intermediate language scripts"
        family = "AsmInject"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "100"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {09 4c 00 6f 00 61 00 64 00 00 15 45 00 6e 00 74 00 72 00 79 00 70 00 6f 00 69 00 6e 00 74 00 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_MSIL_AsmInject_I_2147711022_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:MSIL/AsmInject.I"
        threat_id = "2147711022"
        type = "VirTool"
        platform = "MSIL: .NET intermediate language scripts"
        family = "AsmInject"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "CompressShell" ascii //weight: 1
        $x_1_2 = "NtSetInformationProcess" ascii //weight: 1
        $x_1_3 = "VirtualProtect" ascii //weight: 1
        $x_1_4 = "Confuser" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


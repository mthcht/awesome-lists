rule Trojan_MSIL_ShellInject_NEAB_2147836980_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/ShellInject.NEAB!MTB"
        threat_id = "2147836980"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "ShellInject"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "14"
        strings_accuracy = "High"
    strings:
        $x_10_1 = {13 06 11 04 11 05 11 06 28 07 00 00 06 13 07 20 3a 04 00 00 16 09 28 01 00 00 06 13 08 11 08 7e 0c 00 00 0a 11 07 8e 69 20 00 30 00 00 1f 40 28 03 00 00 06 13 09 11 08 11 09 11 07 11 07 8e 69 12 0a 28 04 00 00 06}  //weight: 10, accuracy: High
        $x_2_2 = "DecryptShellcode" ascii //weight: 2
        $x_2_3 = "WriteProcessMemory" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_ShellInject_NEAA_2147838071_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/ShellInject.NEAA!MTB"
        threat_id = "2147838071"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "ShellInject"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_7_1 = {02 8e 69 8d 01 00 00 01 0a 16 0b 38 13 00 00 00 06 07 02 07 91 03 07 03 8e 69 5d 91 61 d2 9c 07 17 58 0b 07 02 8e 69}  //weight: 7, accuracy: High
        $x_3_2 = "/C powershell.exe Add-MpPreference -ExclusionExtension exe; powershell.exe Add-MpPreference -ExclusionExtension dll" wide //weight: 3
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_ShellInject_DA_2147941682_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/ShellInject.DA!MTB"
        threat_id = "2147941682"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "ShellInject"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "41"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "powershell.exe" ascii //weight: 10
        $x_10_2 = "shellcode" ascii //weight: 10
        $x_10_3 = "CreateObject(Replace(" ascii //weight: 10
        $x_10_4 = "reg add \"HKCU\\Software\\Classes\\.pwn\\Shell\\Open\\command" ascii //weight: 10
        $x_1_5 = "a*m*s*i.*********************dl******l*" ascii //weight: 1
        $x_1_6 = "A**m*siS**c*a*******n*Buf*f*er" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((4 of ($x_10_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}


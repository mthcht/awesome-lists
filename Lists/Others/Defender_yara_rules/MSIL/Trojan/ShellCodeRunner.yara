rule Trojan_MSIL_ShellCodeRunner_CXF_2147851161_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/ShellCodeRunner.CXF!MTB"
        threat_id = "2147851161"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "ShellCodeRunner"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {11 09 11 10 11 08 11 10 9a 1f 10 28 ?? ?? ?? ?? 9c 00 11 10 17 58 13 10 11 10 11 08 8e 69 fe 04 13 11 11 11 2d d9}  //weight: 1, accuracy: Low
        $x_1_2 = "zhwgPHQExloaaD" ascii //weight: 1
        $x_1_3 = "xqMvSkuiE" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_ShellCodeRunner_GP_2147891923_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/ShellCodeRunner.GP!MTB"
        threat_id = "2147891923"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "ShellCodeRunner"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_4_1 = {00 06 07 02 07 91 03 07 03 8e 69 5d 91 61 d2 9c 00 07 17 58 0b 07 02 8e 69 fe 04 0c 08 2d e1}  //weight: 4, accuracy: High
        $x_1_2 = "The program is designed to perform process injection" wide //weight: 1
        $x_1_3 = "CreateRemoteThread Injection" wide //weight: 1
        $x_1_4 = "DLL Injection" wide //weight: 1
        $x_1_5 = "Process Hollowing" wide //weight: 1
        $x_1_6 = "APC Queue Injection" wide //weight: 1
        $x_1_7 = "XOR Encryption" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_ShellCodeRunner_NR_2147917706_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/ShellCodeRunner.NR!MTB"
        threat_id = "2147917706"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "ShellCodeRunner"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_3_1 = {11 06 11 05 09 11 04 6f ?? 00 00 0a 16 73 ?? 00 00 0a 13 07 16 fe 0e ee 01}  //weight: 3, accuracy: Low
        $x_1_2 = "RVirus.pdb" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_ShellCodeRunner_RP_2147917846_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/ShellCodeRunner.RP!MTB"
        threat_id = "2147917846"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "ShellCodeRunner"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "28"
        strings_accuracy = "High"
    strings:
        $x_1_1 = ".win Tools.exe" ascii //weight: 1
        $x_1_2 = "BlockNetwork" ascii //weight: 1
        $x_1_3 = "AddScheduledTask" ascii //weight: 1
        $x_1_4 = ".msvcp120.dll" ascii //weight: 1
        $x_1_5 = ".msvcr120.dll" ascii //weight: 1
        $x_1_6 = ".w10.rar" ascii //weight: 1
        $x_1_7 = ".w7.rar" ascii //weight: 1
        $x_1_8 = "QzpcUHJvZ3JhbSBGaWxlc1" wide //weight: 1
        $x_10_9 = "FWQGWQ231241ASF" wide //weight: 10
        $x_10_10 = {09 11 06 07 11 06 91 08 11 06 08 8e 69 5d 91 61 d2 9c 11 06 17 58 13 06 11 06 07 8e 69 32}  //weight: 10, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_ShellCodeRunner_NS_2147923058_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/ShellCodeRunner.NS!MTB"
        threat_id = "2147923058"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "ShellCodeRunner"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_3_1 = {ff 16 fe 0e ?? ?? ?? ?? 2b 25 00 09 fe 0c ?? ?? ?? 00 07 fe 0c ?? ?? ?? ?? 93 28 15 00 00 0a 9c 00 fe 0c ?? ?? ?? ?? 17 58 fe 0e}  //weight: 3, accuracy: Low
        $x_2_2 = "CalistirmaFonksiyonu" ascii //weight: 2
        $x_1_3 = "Spotifys.exe" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_ShellCodeRunner_NS_2147923058_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/ShellCodeRunner.NS!MTB"
        threat_id = "2147923058"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "ShellCodeRunner"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "Shellcode injected and executed using EnumUILanguagesW in Notepad process!" wide //weight: 2
        $x_1_2 = "execute shellcode using EnumUILanguagesW in the target process!" wide //weight: 1
        $x_1_3 = "create remote thread in the target process!" wide //weight: 1
        $x_1_4 = "write shellcode to the remote process memory!" wide //weight: 1
        $x_1_5 = "allocate memory in the remote process!" wide //weight: 1
        $x_1_6 = "jiamiA_X_B.Properties.Resources" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_ShellCodeRunner_GA_2147924833_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/ShellCodeRunner.GA!MTB"
        threat_id = "2147924833"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "ShellCodeRunner"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {06 11 04 06 11 04 91 07 11 04 07 8e 69 5d 91 61 d2 9c 11 04 17 58 13 04}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_ShellCodeRunner_GAF_2147945454_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/ShellCodeRunner.GAF!MTB"
        threat_id = "2147945454"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "ShellCodeRunner"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {2f 00 4f 00 69 00 50 00 41 00 41 00 41 00 41 00 59 00 44 00 48 00 53 00 69 00 65 00 56 00 6b 00 69 00 31 00 49 00 3d}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


rule Trojan_MSIL_Startun_AS_2147786449_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Startun.AS!MTB"
        threat_id = "2147786449"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Startun"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "24"
        strings_accuracy = "High"
    strings:
        $x_3_1 = "Nitro Generator_ProcessedByFody" ascii //weight: 3
        $x_3_2 = "ReadExistingAssembly" ascii //weight: 3
        $x_3_3 = "ReadFromEmbeddedResources" ascii //weight: 3
        $x_3_4 = "ContainsKey" ascii //weight: 3
        $x_3_5 = "costura.injectordll.dll" ascii //weight: 3
        $x_3_6 = "uniqueId" ascii //weight: 3
        $x_3_7 = "costura.injectordll.pdb" ascii //weight: 3
        $x_3_8 = "GetExecutingAssembly" ascii //weight: 3
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Startun_BL_2147812539_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Startun.BL!MTB"
        threat_id = "2147812539"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Startun"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "9"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "files **not** encrypted!" wide //weight: 1
        $x_1_2 = " files were **encrypted successfully**" wide //weight: 1
        $x_1_3 = "ransomware" wide //weight: 1
        $x_1_4 = "StringDecryptor" wide //weight: 1
        $x_1_5 = "VirtualBox" wide //weight: 1
        $x_1_6 = "logs/Sandboxie" wide //weight: 1
        $x_1_7 = "**Debugger: **" wide //weight: 1
        $x_1_8 = "Select * from Win32_ComputerSystem" wide //weight: 1
        $x_1_9 = "The key-logger is already running" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Startun_SPH_2147846380_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Startun.SPH!MTB"
        threat_id = "2147846380"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Startun"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {03 17 8d 50 00 00 01 25 16 1f 3d 9d 6f ?? ?? ?? 0a 13 06 11 06 17 9a 6f ?? ?? ?? 0a 28 ?? ?? ?? 0a 13 04 11 06 16 9a 6f ?? ?? ?? 0a 72 e9 02 00 70 28 ?? ?? ?? 0a 13 07 11 07 2c 24}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Startun_PTJG_2147903520_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Startun.PTJG!MTB"
        threat_id = "2147903520"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Startun"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {6f 36 00 00 0a 13 05 73 37 00 00 0a 13 06 11 06 08 20 96 00 00 00 20 c8 00 00 00 6f 2c 00 00 0a 6a 28 ?? 00 00 06 6f 38 00 00 0a}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


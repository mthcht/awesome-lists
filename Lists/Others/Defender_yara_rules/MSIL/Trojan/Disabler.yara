rule Trojan_MSIL_Disabler_EM_2147847301_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Disabler.EM!MTB"
        threat_id = "2147847301"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Disabler"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {d9 a7 b0 23 9f 53 30 78 46 bf c0 f9 50 ec b8 95 a3 a6 8e 60 1b d2 e0 07 86 3b a6 27 78 95 4b 87}  //weight: 2, accuracy: High
        $x_1_2 = "Healer.pdb" ascii //weight: 1
        $x_1_3 = "CreateEncryptor" ascii //weight: 1
        $x_1_4 = "ToBase64String" ascii //weight: 1
        $x_1_5 = "AesCryptoServiceProvider" ascii //weight: 1
        $x_1_6 = "RSACryptoServiceProvider" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Disabler_EM_2147847301_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Disabler.EM!MTB"
        threat_id = "2147847301"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Disabler"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {fe 0e 11 00 fe 0c 11 00 fe 0c 11 00 20 01 00 00 00 62 61 fe 0e 11 00 fe 0c 11 00 fe 0c 13 00 58 fe 0e 11 00 fe 0c 11 00 fe 0c 11 00 20 06 00 00 00 62 61 fe 0e 11 00 fe 0c 11 00 fe 0c 14 00 58 fe 0e 11 00 fe 0c 11 00 fe 0c 11 00 20 0b 00 00 00 64 61 fe 0e 11 00 fe 0c 11 00 fe 0c 15 00 58 fe 0e 11 00 fe 0c 13 00 20 0c 00 00 00 62 fe 0c 13 00 59 fe 0c 14 00 61 fe 0c 11 00 59 fe 0e 11 00 fe 0c 11 00 76 6c 6d 58 13 04 11 08 07 17 59 40 50 00 00 00 06 16 3e 49 00 00 00 11 04 11 06 61}  //weight: 2, accuracy: High
        $x_2_2 = "offDef.exe" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Disabler_NBL_2147900614_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Disabler.NBL!MTB"
        threat_id = "2147900614"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Disabler"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {08 1b 62 08 58 11 04 61 0c 11 05 18 58 49 13 04 11 04 39 1d 00 00 00 09 1b 62 09 58 11 04 61 0d 11 05 18 d3 18 5a 58 13 05 11 05 49 25 13 04 3a cc ff ff ff}  //weight: 1, accuracy: High
        $x_1_2 = "SOFTWARE\\Microsoft\\Windows Defender\\Features" ascii //weight: 1
        $x_1_3 = "SOFTWARE\\Policies\\Microsoft\\Windows Defender Security Center\\Notifications" ascii //weight: 1
        $x_1_4 = "SOFTWARE\\Policies\\Microsoft\\Windows\\WindowsUpdate" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Disabler_NN_2147901184_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Disabler.NN!MTB"
        threat_id = "2147901184"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Disabler"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {0b 16 0c 2b 18 07 08 18 5b 02 08 18 6f 41 ?? ?? ?? ?? ?? ?? ?? ?? 00 0a 9c 08 18 58 0c 08 06 32 e4 07 0d de 1f}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Disabler_GZZ_2147901990_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Disabler.GZZ!MTB"
        threat_id = "2147901990"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Disabler"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {2d 47 06 02 1f 2e 28 ?? ?? ?? 06 12 01 fe 15 0b 00 00 02 25 17 12 01 28 ?? ?? ?? 06 26 25 15 1a 15 14 14 7e 14 00 00 0a 14 14 14 14 28 ?? ?? ?? 06 26 20 d0 07 00 00 28 ?? ?? ?? 0a 28 ?? ?? ?? 06 26 06 28 ?? ?? ?? 06 26 2a}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Disabler_ST_2147935953_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Disabler.ST!MTB"
        threat_id = "2147935953"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Disabler"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "$ErrorActionPreference = \"SilentlyContinue\"" ascii //weight: 2
        $x_2_2 = "        Write-Host \"This is a Hyper-V Virtual Machine running on physical host $physicalHost\"" ascii //weight: 2
        $x_2_3 = "    $vmwareServices = @(\"vmdebug\", \"vmmouse\", \"VMTools\", \"VMMEMCTL\", \"tpautoconnsvc\", \"tpvcgateway\", \"vmware\", \"wmci\", \"vmx86\")" ascii //weight: 2
        $x_2_4 = "    $biosVersion = Get-RegistryValueString -Key \"HKLM\\HARDWARE\\DESCRIPTION\\System\" -ValueName \"SystemBiosVersion\"" ascii //weight: 2
        $x_2_5 = "Invoke-SelfReplication" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Disabler_ND_2147939165_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Disabler.ND!MTB"
        threat_id = "2147939165"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Disabler"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "12"
        strings_accuracy = "High"
    strings:
        $x_3_1 = "You were encrypted by Clutter, good luck..." wide //weight: 3
        $x_2_2 = "worm_tool.sys" wide //weight: 2
        $x_1_3 = "minecraft_cheats_2020.Properties.Resources" wide //weight: 1
        $x_1_4 = "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run" wide //weight: 1
        $x_2_5 = "ransom_voice.vbs" wide //weight: 2
        $x_1_6 = "DownloadFile" ascii //weight: 1
        $x_1_7 = "worm_locker" wide //weight: 1
        $x_1_8 = "DisableTaskMgr" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


rule Trojan_MSIL_Vimditator_IF_2147797662_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Vimditator.IF!MTB"
        threat_id = "2147797662"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Vimditator"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Users\\Welcome\\Documents\\WindowsFormsApp10\\WindowsFormsApp10\\bin\\Debug\\CryptoObfuscator_Output\\PAGV.pdb" ascii //weight: 1
        $x_1_2 = "PAGV.exe" wide //weight: 1
        $x_1_3 = "PAGV&&" ascii //weight: 1
        $x_1_4 = "PAGV.Properties" ascii //weight: 1
        $x_1_5 = "ProcessHandle" ascii //weight: 1
        $x_1_6 = "ProcessInformationClass" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Vimditator_AVM_2147841225_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Vimditator.AVM!MTB"
        threat_id = "2147841225"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Vimditator"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {13 04 1f 23 28 ?? ?? ?? 0a 72 37 00 00 70 28 ?? ?? ?? 0a 13 05 11 05 18 18 73 07 00 00 0a 13 06 11 06 11 04 16 11 04 8e 69}  //weight: 2, accuracy: Low
        $x_1_2 = "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run" wide //weight: 1
        $x_1_3 = "This assembly is protected by an unregistered version of IntelliLock" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Vimditator_SL_2147921711_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Vimditator.SL!MTB"
        threat_id = "2147921711"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Vimditator"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {06 72 ad 00 00 70 6f 2a 00 00 0a 10 00 dd 0d 00 00 00}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Vimditator_SL_2147921711_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Vimditator.SL!MTB"
        threat_id = "2147921711"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Vimditator"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {16 2d 0b 2b 0b 72 61 00 00 70 2b 07 2b 0c de 1a 07 2b f2 6f 1f 00 00 0a 2b f2 0a 2b f1}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Vimditator_AWWA_2147944050_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Vimditator.AWWA!MTB"
        threat_id = "2147944050"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Vimditator"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "Low"
    strings:
        $x_3_1 = {1f 09 0b 05 04 07 5d 9a 28 ?? ?? 00 0a 03 28 ?? 02 00 06 28 ?? ?? 00 0a 0a 2b 00 06 2a}  //weight: 3, accuracy: Low
        $x_2_2 = {02 03 66 5f 02 66 03 5f 60 8c ?? 00 00 01 0a 2b 00 06 2a}  //weight: 2, accuracy: Low
        $x_2_3 = {03 08 02 03 08 91 08 04 28 ?? ?? 00 06 9c 08 17 d6 0c 08 07 31 ea}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


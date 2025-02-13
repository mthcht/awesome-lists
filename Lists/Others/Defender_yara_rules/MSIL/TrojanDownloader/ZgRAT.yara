rule TrojanDownloader_MSIL_ZgRAT_A_2147893350_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:MSIL/ZgRAT.A!MTB"
        threat_id = "2147893350"
        type = "TrojanDownloader"
        platform = "MSIL: .NET intermediate language scripts"
        family = "ZgRAT"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {02 8e 69 8d ?? 00 00 01 0a 16 0b}  //weight: 2, accuracy: Low
        $x_2_2 = {06 07 02 07 91 20 ?? ?? ?? 83 28 ?? 00 00 06 28 ?? ?? 00 0a 59 d2 9c 07 17 58 0b 07 02 8e 69}  //weight: 2, accuracy: Low
        $x_1_3 = "GetMethod" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_MSIL_ZgRAT_B_2147895755_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:MSIL/ZgRAT.B!MTB"
        threat_id = "2147895755"
        type = "TrojanDownloader"
        platform = "MSIL: .NET intermediate language scripts"
        family = "ZgRAT"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "antivmm" ascii //weight: 2
        $x_2_2 = "CheckForVirtualMachine" ascii //weight: 2
        $x_1_3 = "GetDelegateForFunctionPointer" ascii //weight: 1
        $x_1_4 = "GetProcessById" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_MSIL_ZgRAT_C_2147896942_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:MSIL/ZgRAT.C!MTB"
        threat_id = "2147896942"
        type = "TrojanDownloader"
        platform = "MSIL: .NET intermediate language scripts"
        family = "ZgRAT"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {06 08 06 91 11 ?? 06 11 ?? 6f ?? ?? 00 0a 5d 6f ?? ?? 00 0a 61 d2 9c 06 17 58 0a 06 08 8e 69}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_MSIL_ZgRAT_F_2147901226_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:MSIL/ZgRAT.F!MTB"
        threat_id = "2147901226"
        type = "TrojanDownloader"
        platform = "MSIL: .NET intermediate language scripts"
        family = "ZgRAT"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {06 11 02 72 ?? 00 00 70 28 ?? 00 00 06 28 ?? 00 00 2b 28 ?? 00 00 06 26 20}  //weight: 2, accuracy: Low
        $x_2_2 = {04 03 04 58 11}  //weight: 2, accuracy: High
        $x_1_3 = "Reverse" ascii //weight: 1
        $x_1_4 = "ToArray" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_MSIL_ZgRAT_G_2147902092_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:MSIL/ZgRAT.G!MTB"
        threat_id = "2147902092"
        type = "TrojanDownloader"
        platform = "MSIL: .NET intermediate language scripts"
        family = "ZgRAT"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {06 11 06 72 ?? ?? 00 70 28 ?? 00 00 06 28 ?? 00 00 2b 28 ?? 00 00 06 26 20}  //weight: 2, accuracy: Low
        $x_1_2 = "Reverse" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_MSIL_ZgRAT_H_2147902457_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:MSIL/ZgRAT.H!MTB"
        threat_id = "2147902457"
        type = "TrojanDownloader"
        platform = "MSIL: .NET intermediate language scripts"
        family = "ZgRAT"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {70 20 00 01 00 00 14 14 14 6f ?? 00 00 0a 26 20}  //weight: 2, accuracy: Low
        $x_1_2 = "Reverse" ascii //weight: 1
        $x_1_3 = "GetExportedTypes" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


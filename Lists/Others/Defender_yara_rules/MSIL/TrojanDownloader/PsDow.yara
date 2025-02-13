rule TrojanDownloader_MSIL_PsDow_C_2147838236_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:MSIL/PsDow.C!MTB"
        threat_id = "2147838236"
        type = "TrojanDownloader"
        platform = "MSIL: .NET intermediate language scripts"
        family = "PsDow"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "12"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "ALwBQAG8AdwBlAHIAcwBoAGUAbABsAC8AdABlAHMAdAAuAHQAeAB0ACIAKQA=" wide //weight: 2
        $x_2_2 = "SQBFAFgAIAAoAG4AZQB3AC0AbwBiAGoAZQBjAHQAIABzAHkAcwB0AGUAbQAuAG4AZQB0AC4" wide //weight: 2
        $x_2_3 = "AdwBlAGIAYwBsAGkAZQBuAHQAKQAuAGQAbwB3AG4AbABvAGEAZABzAHQAcgBpAG4AZwA" wide //weight: 2
        $x_2_4 = "powershell.exe" wide //weight: 2
        $x_2_5 = "-enc" wide //weight: 2
        $x_1_6 = "set_WindowStyle" ascii //weight: 1
        $x_1_7 = "set_StartInfo" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_MSIL_PsDow_D_2147840496_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:MSIL/PsDow.D!MTB"
        threat_id = "2147840496"
        type = "TrojanDownloader"
        platform = "MSIL: .NET intermediate language scripts"
        family = "PsDow"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {61 d1 6f 0c 00 00 0a 26 fe}  //weight: 2, accuracy: High
        $x_1_2 = "ToCharArray" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_MSIL_PsDow_F_2147845480_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:MSIL/PsDow.F!MTB"
        threat_id = "2147845480"
        type = "TrojanDownloader"
        platform = "MSIL: .NET intermediate language scripts"
        family = "PsDow"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "JITStarter" ascii //weight: 2
        $x_2_2 = "Confuser.Core" ascii //weight: 2
        $x_1_3 = "ProcessWindowStyle" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_MSIL_PsDow_E_2147847018_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:MSIL/PsDow.E!MTB"
        threat_id = "2147847018"
        type = "TrojanDownloader"
        platform = "MSIL: .NET intermediate language scripts"
        family = "PsDow"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "ProcessWindowStyle" ascii //weight: 1
        $x_2_2 = "JITStarter" ascii //weight: 2
        $x_2_3 = "Skater_NET_Obfuscator_" ascii //weight: 2
        $x_2_4 = "RustemSoft.Skater" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


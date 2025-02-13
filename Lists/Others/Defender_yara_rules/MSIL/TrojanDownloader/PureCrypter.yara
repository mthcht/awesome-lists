rule TrojanDownloader_MSIL_PureCrypter_B_2147840918_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:MSIL/PureCrypter.B!MTB"
        threat_id = "2147840918"
        type = "TrojanDownloader"
        platform = "MSIL: .NET intermediate language scripts"
        family = "PureCrypter"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {09 06 1f 0c 58 4a 18 5b 1f 10 07 06 1f 0c 58 4a 18 6f}  //weight: 2, accuracy: High
        $x_1_2 = "GetMethod" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_MSIL_PureCrypter_E_2147844623_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:MSIL/PureCrypter.E!MTB"
        threat_id = "2147844623"
        type = "TrojanDownloader"
        platform = "MSIL: .NET intermediate language scripts"
        family = "PureCrypter"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {8e 69 5d 91 7e ?? 00 00 04 11 03 91 61 d2 6f 02 00 00 0a}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_MSIL_PureCrypter_APC_2147845845_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:MSIL/PureCrypter.APC!MTB"
        threat_id = "2147845845"
        type = "TrojanDownloader"
        platform = "MSIL: .NET intermediate language scripts"
        family = "PureCrypter"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {72 6b 00 00 70 28 1f 00 00 06 13 01 38 00 00 00 00 28 14 00 00 0a 11 01 28 21 00 00 06 72 b1 00 00 70 7e 15 00 00 0a 6f 16 00 00 0a 28 22 00 00 06 13 03}  //weight: 1, accuracy: High
        $x_1_2 = {20 00 0c 00 00 28 ?? ?? ?? 06 38 00 00 00 00 dd 10 00 00 00 26 38 00 00 00 00 dd 05 00 00 00 38 00 00 00 00 02 28 ?? ?? ?? 0a 74 17 00 00 01 6f ?? ?? ?? 0a 73 1a 00 00 0a 13 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_MSIL_PureCrypter_APY_2147896128_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:MSIL/PureCrypter.APY!MTB"
        threat_id = "2147896128"
        type = "TrojanDownloader"
        platform = "MSIL: .NET intermediate language scripts"
        family = "PureCrypter"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {14 0a 38 2c 00 00 00 00 28 11 00 00 0a 02 72 0d 00 00 70 28 08 00 00 06 6f 12 00 00 0a 28 13 00 00 0a 28 06 00 00 06 0a dd 06 00 00 00 26 dd 00 00 00 00 06 2c d1}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_MSIL_PureCrypter_G_2147901333_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:MSIL/PureCrypter.G!MTB"
        threat_id = "2147901333"
        type = "TrojanDownloader"
        platform = "MSIL: .NET intermediate language scripts"
        family = "PureCrypter"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {57 3f b6 3f 09 1f 00 00 00 fa 01 33 00 16 00 00 01 00 00 00 8a 01 00 00 86 00 00 00 98 05 00 00 2f 05}  //weight: 2, accuracy: High
        $x_2_2 = "DownloadAsync" wide //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_MSIL_PureCrypter_H_2147910926_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:MSIL/PureCrypter.H!MTB"
        threat_id = "2147910926"
        type = "TrojanDownloader"
        platform = "MSIL: .NET intermediate language scripts"
        family = "PureCrypter"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "Sodgoubg.Dimbgqokaasciald" wide //weight: 2
        $x_2_2 = "Uznkqjicohpnepoounawj" wide //weight: 2
        $x_1_3 = "GetDomain" ascii //weight: 1
        $x_1_4 = "InvokeMember" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_MSIL_PureCrypter_I_2147911964_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:MSIL/PureCrypter.I!MTB"
        threat_id = "2147911964"
        type = "TrojanDownloader"
        platform = "MSIL: .NET intermediate language scripts"
        family = "PureCrypter"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {11 02 16 11 02 8e 69}  //weight: 2, accuracy: High
        $x_2_2 = {11 02 8e 69 20 40 42 0f}  //weight: 2, accuracy: High
        $x_2_3 = {20 80 3e 00 00 8d ?? 00 00 01 13 05}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_MSIL_PureCrypter_ARA_2147923214_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:MSIL/PureCrypter.ARA!MTB"
        threat_id = "2147923214"
        type = "TrojanDownloader"
        platform = "MSIL: .NET intermediate language scripts"
        family = "PureCrypter"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {07 11 05 11 04 6f ?? ?? ?? 0a 13 06 08 09 25 17 58 0d 12 06 28 ?? ?? ?? 0a 9c 11 05 17 58 13 05 11 05 07 6f ?? ?? ?? 0a 32 d6}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


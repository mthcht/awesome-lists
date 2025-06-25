rule TrojanDownloader_MSIL_Ader_ARA_2147837236_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:MSIL/Ader.ARA!MTB"
        threat_id = "2147837236"
        type = "TrojanDownloader"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Ader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {11 04 06 09 06 09 8e 69 5d 91 08 06 91 61 d2 9c 06 17 58 0a 06 08 8e 69 32 e6}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_MSIL_Ader_ARA_2147837236_1
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:MSIL/Ader.ARA!MTB"
        threat_id = "2147837236"
        type = "TrojanDownloader"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Ader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {06 09 06 09 8e 69 5d 91 08 06 91 61 d2 6f ?? ?? ?? 0a 06 17 58 0a 06 08 8e 69 32 e2}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_MSIL_Ader_ARA_2147837236_2
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:MSIL/Ader.ARA!MTB"
        threat_id = "2147837236"
        type = "TrojanDownloader"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Ader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {16 0d 2b 15 00 06 08 07 09 91 06 08 91 61 28 ?? ?? ?? 0a 9c 00 09 17 58 0d 09 07 8e 69 fe 04 13 05 11 05 2d df 00 08 17 58 0c 08 06 8e 69 fe 04 13 05 11 05 2d c9}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_MSIL_Ader_ARA_2147837236_3
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:MSIL/Ader.ARA!MTB"
        threat_id = "2147837236"
        type = "TrojanDownloader"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Ader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {70 02 07 6f ?? ?? ?? 0a 03 07 03 6f ?? ?? ?? 0a 5d 6f ?? ?? ?? 0a 61 8c}  //weight: 2, accuracy: Low
        $x_2_2 = {0a 0a 00 07 17 58 0b 07 02 6f ?? ?? ?? 0a fe 04 0c 08 2d c1 06 0d 2b 00 09 2a}  //weight: 2, accuracy: Low
        $x_2_3 = "QzpcXFdpbmRvd3NcXE1pY3Jvc29mdC5ORVRcXEZyYW1ld29ya1xcdjQuMC4zMDMxOVxcUmVnQXNtLmV4ZQ==" wide //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_MSIL_Ader_ABHK_2147838441_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:MSIL/Ader.ABHK!MTB"
        threat_id = "2147838441"
        type = "TrojanDownloader"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Ader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {2b 31 16 2b 31 2b 36 2b 3b 2b 06 2b 07 2b 08 de 14 09 2b f7 08 2b f6 6f 14 00 00 0a 2b f1 09 6f 17 00 00 0a dc 18 2c 09 2b 1d 6f 15 00 00 0a 13 04 de 4e 07}  //weight: 2, accuracy: High
        $x_1_2 = "GetResponseStream" ascii //weight: 1
        $x_1_3 = "GetTypes" ascii //weight: 1
        $x_1_4 = "InvokeMember" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_MSIL_Ader_ARAF_2147839172_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:MSIL/Ader.ARAF!MTB"
        threat_id = "2147839172"
        type = "TrojanDownloader"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Ader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {09 08 11 04 08 8e 69 5d 91 07 11 04 91 61 d2 6f ?? ?? ?? 0a 11 04 13 05 11 05 17 58 13 04 11 04 07 8e 69 32 db}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_MSIL_Ader_ARAG_2147839814_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:MSIL/Ader.ARAG!MTB"
        threat_id = "2147839814"
        type = "TrojanDownloader"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Ader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {09 06 11 04 06 8e 69 5d 91 08 11 04 91 61 d2 6f ?? ?? ?? 0a 11 04 17 58 13 04 11 04 08 8e 69}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_MSIL_Ader_ARAA_2147840192_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:MSIL/Ader.ARAA!MTB"
        threat_id = "2147840192"
        type = "TrojanDownloader"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Ader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {06 03 11 06 91 07 11 06 07 8e 69 5d 91 61 08 61 d2 6f ?? ?? ?? 0a 00 00 11 06 17 58 13 06 11 06 03 8e 69 fe 04 13 07 11 07 2d d4}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_MSIL_Ader_ARAX_2147840696_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:MSIL/Ader.ARAX!MTB"
        threat_id = "2147840696"
        type = "TrojanDownloader"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Ader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_5_1 = {09 17 58 0d 09 20 00 01 00 00 5d 0d 11 05 11 09 09 94 58 13 05 11 05 20 00 01 00 00 5d 13 05 11 09 09 94 13 07 11 09 09 11 09 11 05 94 9e 11 09 11 05 11 07 9e 11 09 11 09 09 94 11 09 11 05 94 58 20 00 01 00 00 5d 94 13 06 11 0a 11 04 07 11 04 91 11 06 61 d2 9c 11 04 17 58 13 04 11 04 07 8e 69 16 2d b7 32 99}  //weight: 5, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_MSIL_Ader_ARAQ_2147840698_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:MSIL/Ader.ARAQ!MTB"
        threat_id = "2147840698"
        type = "TrojanDownloader"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Ader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_5_1 = {09 11 04 18 5b 07 11 04 18 6f 15 00 00 0a 1f 10 28 16 00 00 0a 9c 11 04 18 58 13 04 11 04 08 32 df}  //weight: 5, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_MSIL_Ader_ABNI_2147843709_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:MSIL/Ader.ABNI!MTB"
        threat_id = "2147843709"
        type = "TrojanDownloader"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Ader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_3_1 = {0a de 03 26 de 00 06 6f ?? ?? ?? 0a 2c e2 28 ?? ?? ?? 0a 06 16 6f ?? ?? ?? 0a 6f ?? ?? ?? 0a 72 ?? ?? ?? 70 7e ?? ?? ?? 0a 6f ?? ?? ?? 0a 28 ?? ?? ?? 0a 2a 43 00 06 72 ?? ?? ?? 70 28 ?? ?? ?? 06 6f}  //weight: 3, accuracy: Low
        $x_1_2 = "Replace" ascii //weight: 1
        $x_1_3 = "GetType" ascii //weight: 1
        $x_1_4 = "FromBase64String" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_MSIL_Ader_ARZ_2147845923_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:MSIL/Ader.ARZ!MTB"
        threat_id = "2147845923"
        type = "TrojanDownloader"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Ader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_5_1 = {09 11 04 18 5b 07 11 04 18 6f 16 00 00 0a 1f 10 28 17 00 00 0a 9c 11 04 18 58 13 04 11 04 08 32 df}  //weight: 5, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_MSIL_Ader_ARBE_2147845924_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:MSIL/Ader.ARBE!MTB"
        threat_id = "2147845924"
        type = "TrojanDownloader"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Ader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {06 09 11 04 09 8e 69 5d 91 08 11 04 91 61 d2 6f ?? ?? ?? 0a 11 04 17 58 13 04 11 04 08 8e 69 32 df}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_MSIL_Ader_ABSB_2147846498_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:MSIL/Ader.ABSB!MTB"
        threat_id = "2147846498"
        type = "TrojanDownloader"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Ader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {16 2d 04 2b 24 2b 29 1a 2c 1d 7e ?? 00 00 04 7e ?? 00 00 04 7e ?? 00 00 04 2b 18 2b 1d 2b 1e 2b 23 2b 28 2b 2d 2b 32 de 39 28 ?? 00 00 06 2b d5 0a 2b d4 28 ?? 00 00 06 2b e1 06 2b e0 28 ?? 00 00 06 2b db 28 ?? 00 00 06 2b d6 28 ?? 00 00 2b 2b d1 28 ?? 00 00 2b 2b cc 0b 2b cb}  //weight: 5, accuracy: Low
        $x_1_2 = "FromBase64String" ascii //weight: 1
        $x_1_3 = "Reverse" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_MSIL_Ader_CSTY_2147846590_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:MSIL/Ader.CSTY!MTB"
        threat_id = "2147846590"
        type = "TrojanDownloader"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Ader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {11 02 2a 16 13 03 38 ?? ?? ?? ?? 11 02 11 03 18 5b 11 04 11 03 18 6f ?? ?? ?? ?? 1f 10 28 ?? ?? ?? ?? 9c 38 ?? ?? ?? ?? 11 01 18 5b 8d}  //weight: 5, accuracy: Low
        $x_1_2 = {68 00 74 00 74 00 70 00 3a 00 2f 00 2f 00 31 00 32 00 33 00 63 00 72 00 61 00 63 00 6b 00 66 00 69 00 6e 00 64 00 65 00 72 00 2e 00 63 00 6f 00 6d 00 2f 00 31 00 32 00 33 00 63 00 72 00 61 00 63 00 6b 00 66 00 69 00 6e 00 64 00 65 00 72 00 2e 00 63 00 6f 00 6d 00 2f 00 6a 00 64 00 66 00 68 00 65 00 72 00 2f 00 70 00 61 00 6e 00 65 00 6c 00 2f 00 75 00 70 00 6c 00 6f 00 61 00 64 00 73 00 2f 00 [0-31] 2e 00 70 00 6e 00 67 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_MSIL_Ader_ARBC_2147846652_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:MSIL/Ader.ARBC!MTB"
        threat_id = "2147846652"
        type = "TrojanDownloader"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Ader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_5_1 = {7e 1b 00 00 04 11 04 7e 1b 00 00 04 11 04 91 20 c8 03 00 00 59 d2 9c 00 11 04 17 58 13 04 11 04 7e 1b 00 00 04 8e 69 fe 04 13 05 11 05 2d d0}  //weight: 5, accuracy: High
        $x_5_2 = "https://www.fintran.site/fl/968" ascii //weight: 5
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_MSIL_Ader_CXFW_2147850811_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:MSIL/Ader.CXFW!MTB"
        threat_id = "2147850811"
        type = "TrojanDownloader"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Ader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "https://cdn.discordapp.com/attachments/1104504576914243625/1114307294042275870/OrionStarter.dll" ascii //weight: 1
        $x_1_2 = "https://pastebin.com/HP2Y4Zez" ascii //weight: 1
        $x_1_3 = "Destination du jeu non valide" ascii //weight: 1
        $x_1_4 = "N'utilisez pas de paks modifi" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_MSIL_Ader_PAN_2147888527_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:MSIL/Ader.PAN!MTB"
        threat_id = "2147888527"
        type = "TrojanDownloader"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Ader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "188.213.167.248/download/suoni/GAAttesa.wav" ascii //weight: 1
        $x_1_2 = "DownloadFile" ascii //weight: 1
        $x_1_3 = "HideStartBar" ascii //weight: 1
        $x_1_4 = "KillExplorer" ascii //weight: 1
        $x_1_5 = "mciSendCommandA" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_MSIL_Ader_ABIT_2147896472_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:MSIL/Ader.ABIT!MTB"
        threat_id = "2147896472"
        type = "TrojanDownloader"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Ader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_3_1 = {06 0c 16 0d 08 12 03 28 ?? ?? ?? 0a 06 07 02 07 18 6f ?? ?? ?? 0a 1f 10 28 ?? ?? ?? 0a 6f ?? ?? ?? 0a de 0a 09 2c 06 08 28 ?? ?? ?? 0a dc 07 18 58 0b 07 02 6f ?? ?? ?? 0a 32 c5 06 6f ?? ?? ?? 0a 28 ?? ?? ?? 2b 2a}  //weight: 3, accuracy: Low
        $x_1_2 = "Uwzosefjkpcvtowkk" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_MSIL_Ader_ARC_2147899493_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:MSIL/Ader.ARC!MTB"
        threat_id = "2147899493"
        type = "TrojanDownloader"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Ader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_5_1 = {06 09 11 04 09 8e 69 5d 91 08 11 04 91 61 d2 6f 2b 00 00 0a 11 04 17 58 13 04 11 04 08 8e 69 32 df}  //weight: 5, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_MSIL_Ader_SS_2147917075_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:MSIL/Ader.SS!MTB"
        threat_id = "2147917075"
        type = "TrojanDownloader"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Ader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {04 05 8e 69 42 ?? ?? ?? 00 04 38 ?? ?? ?? 00 05 8e 69 0a 03 05 16 06 6f 1a 00 00 0a 26 02 05 16 06 28 28 00 00 06 04 06 59 10 02 04 16 42 ce ff ff ff}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_MSIL_Ader_MBWE_2147927870_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:MSIL/Ader.MBWE!MTB"
        threat_id = "2147927870"
        type = "TrojanDownloader"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Ader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "valorantskinschanger.com/nytrajack" wide //weight: 2
        $x_1_2 = "4e023f43e189" ascii //weight: 1
        $x_1_3 = "Installer_sharp" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_MSIL_Ader_ASQA_2147938547_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:MSIL/Ader.ASQA!MTB"
        threat_id = "2147938547"
        type = "TrojanDownloader"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Ader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {0a 03 16 03 8e 69 6f ?? 00 00 0a 13 01 20 01 00 00 00 7e ?? 02 00 04 7b ?? 02 00 04 3a ?? ff ff ff 26 20 01 00 00 00 38 ?? ff ff ff 11 03 72 93 00 00 70 28 ?? 00 00 0a 6f ?? 00 00 0a 20 02 00 00 00 7e ?? 02 00 04 7b ?? 02 00 04 39 ?? ff ff ff 26 20 01 00 00 00 38}  //weight: 5, accuracy: Low
        $x_1_2 = "FromBase64String" ascii //weight: 1
        $x_1_3 = "CreateDecryptor" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_MSIL_Ader_ADXA_2147944262_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:MSIL/Ader.ADXA!MTB"
        threat_id = "2147944262"
        type = "TrojanDownloader"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Ader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {08 91 02 08 07 5d 6f ?? 00 00 0a 61 d2 9c 16 2d e9 1a 2c e6 08 17 58 0c 08 03 8e 69 32 dc 06 2a 03 2b c0 0a 2b c6 02 2b c5 6f ?? 00 00 0a 2b c0 0b 2b bf 0c 2b bf 06 2b c3 08 2b c2 03 2b c1}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_MSIL_Ader_AQXA_2147944636_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:MSIL/Ader.AQXA!MTB"
        threat_id = "2147944636"
        type = "TrojanDownloader"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Ader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_4_1 = {72 1c 01 00 70 28 ?? 00 00 0a 0a 72 4e 01 00 70 28 ?? 00 00 0a 0b 73 ?? 00 00 0a 0c 08 06 6f ?? 00 00 0a 08 07 6f ?? 00 00 0a 08 6f ?? 00 00 0a 02 16 02 8e 69 6f ?? 00 00 0a 0d dd}  //weight: 4, accuracy: Low
        $x_1_2 = "FromBase64String" ascii //weight: 1
        $x_1_3 = "CreateDecryptor" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


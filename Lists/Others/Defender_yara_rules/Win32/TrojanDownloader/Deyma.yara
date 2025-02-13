rule TrojanDownloader_Win32_Deyma_DEA_2147760593_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Deyma.DEA!MTB"
        threat_id = "2147760593"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Deyma"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "4350ijy30u945j9f" ascii //weight: 1
        $x_1_2 = "mKAODZBBLB" ascii //weight: 1
        $x_1_3 = "ZmLYfNZsYG" ascii //weight: 1
        $x_1_4 = "nXIIqvTZWQ" ascii //weight: 1
        $x_1_5 = "xIqhEdbUOv" ascii //weight: 1
        $x_1_6 = "wPnrAIyOpe" ascii //weight: 1
        $x_1_7 = "piQkAqrFyQ" ascii //weight: 1
        $x_1_8 = "lTEEzGvSbA" ascii //weight: 1
        $x_1_9 = "OFFPqsoXOe" ascii //weight: 1
        $x_1_10 = "IocWVyYrfk" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

rule TrojanDownloader_Win32_Deyma_DEB_2147760804_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Deyma.DEB!MTB"
        threat_id = "2147760804"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Deyma"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "4350ijy30u945j9f" ascii //weight: 1
        $x_1_2 = "suSzdXzzGv" ascii //weight: 1
        $x_1_3 = "LVsavBvZsi" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (2 of ($x*))
}

rule TrojanDownloader_Win32_Deyma_DEC_2147761691_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Deyma.DEC!MTB"
        threat_id = "2147761691"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Deyma"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "11"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "4350ijy30u945j9f" ascii //weight: 10
        $x_1_2 = "NhzcMuAgeN" ascii //weight: 1
        $x_1_3 = "ilCezcTgkR" ascii //weight: 1
        $x_1_4 = "DYtXKSkRZK" ascii //weight: 1
        $x_1_5 = "iouwJVtdKc" ascii //weight: 1
        $x_1_6 = "DDPIgVncJv" ascii //weight: 1
        $x_1_7 = "INYaQWGuai" ascii //weight: 1
        $x_1_8 = "NldhyjHaFD" ascii //weight: 1
        $x_1_9 = "ebJiBDtyvi" ascii //weight: 1
        $x_1_10 = "KLXqUdimiL" ascii //weight: 1
        $x_1_11 = "drJPZGhHaD" ascii //weight: 1
        $x_1_12 = "IjuKPKtTfN" ascii //weight: 1
        $x_1_13 = "zWljbpKWMa" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((11 of ($x_1_*))) or
            ((1 of ($x_10_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule TrojanDownloader_Win32_Deyma_AU_2147831262_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Deyma.AU!MTB"
        threat_id = "2147831262"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Deyma"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "PRoNOuRLTELX2dAb3rJwcU32fb3hZVO4SuQp5dNw82v9FS0j4LNT0PHQ1LVa2xGz7NEV7wRwPmDpOG" ascii //weight: 1
        $x_1_2 = "ELYNKLFOQk7CHKovAU==" ascii //weight: 1
        $x_1_3 = "PxMpSTFf8XK=" ascii //weight: 1
        $x_1_4 = "MSYUMcBY7XXhJTcp5KNmTO3oel==" ascii //weight: 1
        $x_1_5 = "Amadey\\Release\\Amadey.pdb" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_Win32_Deyma_SP_2147835404_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Deyma.SP!MTB"
        threat_id = "2147835404"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Deyma"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {8b 55 9c 81 c2 27 01 00 00 2b 55 f4 89 55 a8 8b 45 84 33 85 78 ff ff ff 89 45 84 81 7d e0 0c 01 00 00 77 09}  //weight: 2, accuracy: High
        $x_2_2 = {8b 55 fc 83 c2 01 89 55 fc 83 7d fc 02 73 14 0f b7 45 bc 8b 4d e4 2b c8 81 c1 c0 00 00 00 89 4d cc eb dd}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


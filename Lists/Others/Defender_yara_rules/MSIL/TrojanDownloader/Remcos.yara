rule TrojanDownloader_MSIL_Remcos_NY_2147828706_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:MSIL/Remcos.NY!MTB"
        threat_id = "2147828706"
        type = "TrojanDownloader"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Remcos"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {09 08 06 08 8e 69 5d 91 07 06 91 61 d2 6f ?? 00 00 0a 06 17 58 0a}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_MSIL_Remcos_BJ_2147829363_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:MSIL/Remcos.BJ!MTB"
        threat_id = "2147829363"
        type = "TrojanDownloader"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Remcos"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {16 0b 2b 2b 7e ?? ?? ?? 04 07 7e ?? ?? ?? 04 07 91 7e ?? ?? ?? 04 07 7e ?? ?? ?? 04 8e 69 5d 91 06 58 20 ?? ?? ?? ?? 5f 61 d2 9c 07 17 58 0b 07 7e ?? ?? ?? 04 8e 69 17 59 fe 02 16 fe 01 0c 08 2d}  //weight: 2, accuracy: Low
        $x_1_2 = "rdapp.com" wide //weight: 1
        $x_1_3 = "DownloadData" ascii //weight: 1
        $x_1_4 = "DebuggerNonUserCodeAttribute" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_MSIL_Remcos_SRP_2147834834_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:MSIL/Remcos.SRP!MTB"
        threat_id = "2147834834"
        type = "TrojanDownloader"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Remcos"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {0a 16 0b 2b 1a 13 04 2b f1 06 07 6f ?? ?? ?? 0a 13 05 11 04 11 05 6f ?? ?? ?? 0a 07 17 58 0b 07 06 6f ?? ?? ?? 0a 32 e1 14 11 04 28 ?? ?? ?? 2b 0a de 17}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_MSIL_Remcos_SPL_2147836050_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:MSIL/Remcos.SPL!MTB"
        threat_id = "2147836050"
        type = "TrojanDownloader"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Remcos"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "11"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {06 18 2d 05 26 16 0d 2b 03 0c 2b f9 08 12 03 28 ?? ?? ?? 0a 06 03 07 28 ?? ?? ?? 06 6f ?? ?? ?? 0a de 0a 09 2c 06 08 28 ?? ?? ?? 0a dc 07 18 58 0b 07 03 6f ?? ?? ?? 0a 32 c6}  //weight: 5, accuracy: Low
        $x_3_2 = "Othubpm.exe" ascii //weight: 3
        $x_3_3 = "/207.167.64.122/Fvkpkpw.bmp" wide //weight: 3
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_MSIL_Remcos_SPLA_2147836552_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:MSIL/Remcos.SPLA!MTB"
        threat_id = "2147836552"
        type = "TrojanDownloader"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Remcos"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {0d 07 08 6f ?? ?? ?? 0a 08 6f ?? ?? ?? 0a 16 6a 31 39 08 6f ?? ?? ?? 0a 13 04 08 6f ?? ?? ?? 0a 09 11 04 16 11 04 8e 69 6f ?? ?? ?? 0a 09 6f ?? ?? ?? 0a 16 6a 31 14 11 04 2c 10 16 2d bd 09 6f ?? ?? ?? 0a 13 05 18 2c c9 de 54}  //weight: 2, accuracy: Low
        $x_1_2 = "noithathoanggiatn.com/loader/uploads/noicon_Vjaexsoq.bmp" wide //weight: 1
        $x_1_3 = "Lrvundb.Qvguhnnvgqhnsy" wide //weight: 1
        $x_1_4 = "Mntjkewbrt" wide //weight: 1
        $x_1_5 = "Pqtxfdejoynxfqunprtqg" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_MSIL_Remcos_MBBI_2147839698_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:MSIL/Remcos.MBBI!MTB"
        threat_id = "2147839698"
        type = "TrojanDownloader"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Remcos"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "14"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "80.66.75.36" ascii //weight: 10
        $x_1_2 = "Reverse" ascii //weight: 1
        $x_1_3 = "FromBase64String" ascii //weight: 1
        $x_1_4 = "DownloadData" ascii //weight: 1
        $x_1_5 = "ToArray" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_MSIL_Remcos_ARA_2147844014_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:MSIL/Remcos.ARA!MTB"
        threat_id = "2147844014"
        type = "TrojanDownloader"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Remcos"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {72 0d 00 00 70 28 05 00 00 06 0a 28 05 00 00 0a 06 6f 06 00 00 0a 28 07 00 00 0a 28 03 00 00 06 0b dd 03 00 00 00 26 de d6}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_MSIL_Remcos_CXJK_2147849618_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:MSIL/Remcos.CXJK!MTB"
        threat_id = "2147849618"
        type = "TrojanDownloader"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Remcos"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {68 00 74 00 74 00 70 00 3a 00 2f 00 2f 00 38 00 30 00 2e 00 36 00 36 00 2e 00 37 00 35 00 2e 00 33 00 37 00 2f}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_MSIL_Remcos_RDJ_2147889343_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:MSIL/Remcos.RDJ!MTB"
        threat_id = "2147889343"
        type = "TrojanDownloader"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Remcos"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {07 72 01 00 00 70 28 02 00 00 0a 72 33 00 00 70 28 02 00 00 0a 6f 03 00 00 0a 0c 14 0d}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_MSIL_Remcos_CCGV_2147900873_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:MSIL/Remcos.CCGV!MTB"
        threat_id = "2147900873"
        type = "TrojanDownloader"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Remcos"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {0c 2b 0b 72 ?? ?? ?? ?? 2b 0b 2b 10 de 2b 73 ?? ?? ?? ?? 2b ee 28 ?? 00 00 0a 2b ee 0a 2b ed 08 2c 06 08 6f ?? 00 00 0a 1d 2c f7 19 2c f1}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_MSIL_Remcos_ARM_2147922893_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:MSIL/Remcos.ARM!MTB"
        threat_id = "2147922893"
        type = "TrojanDownloader"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Remcos"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {2b 07 2b 0c de 17 07 2b f2 6f ?? 00 00 0a 2b f2 0a 2b f1 07 2c 06 07 6f ?? 00 00 0a dc 2b 7c}  //weight: 2, accuracy: Low
        $x_1_2 = "files.catbox.moe" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_MSIL_Remcos_PZJM_2147936655_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:MSIL/Remcos.PZJM!MTB"
        threat_id = "2147936655"
        type = "TrojanDownloader"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Remcos"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_7_1 = {68 00 74 00 74 00 70 00 3a 00 2f 00 2f 00 31 00 36 00 32 00 2e 00 32 00 33 00 30 00 2e 00 34 00 38 00 2e 00 31 00 38 00 39 00 2f 00 75 00 70 00 6c 00 6f 00 61 00 64 00 73 00 2f 00 [0-15] 2e 00 65 00 78 00 65 00}  //weight: 7, accuracy: Low
        $x_1_2 = "WriteAllBytes" ascii //weight: 1
        $x_1_3 = "GetByteArrayAsync" ascii //weight: 1
        $x_1_4 = "GetTempFileName" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


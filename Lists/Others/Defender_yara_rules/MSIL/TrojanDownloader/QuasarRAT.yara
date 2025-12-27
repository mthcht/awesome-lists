rule TrojanDownloader_MSIL_QuasarRAT_A_2147829071_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:MSIL/QuasarRAT.A!MTB"
        threat_id = "2147829071"
        type = "TrojanDownloader"
        platform = "MSIL: .NET intermediate language scripts"
        family = "QuasarRAT"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "11"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {72 01 00 00 70 28 08 00 00 06 13 00 38 00 00 00 00 11 00 28 06 00 00 06 38}  //weight: 1, accuracy: High
        $x_1_2 = {20 dc 27 00 00 8d 07 00 00 01 13 ?? 38 21 00 11 02 6f ?? 00 00 0a 13 03 38}  //weight: 1, accuracy: Low
        $x_1_3 = "ToArray" ascii //weight: 1
        $x_1_4 = "Reverse" ascii //weight: 1
        $x_1_5 = "SecurityProtocolType" ascii //weight: 1
        $x_1_6 = "MemoryStream" ascii //weight: 1
        $x_1_7 = "HttpWebRequest" ascii //weight: 1
        $x_1_8 = "HttpWebResponse" ascii //weight: 1
        $x_1_9 = "GetType" ascii //weight: 1
        $x_1_10 = "CreateInstance" ascii //weight: 1
        $x_1_11 = "GetMethods" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_MSIL_QuasarRAT_D_2147831383_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:MSIL/QuasarRAT.D!MTB"
        threat_id = "2147831383"
        type = "TrojanDownloader"
        platform = "MSIL: .NET intermediate language scripts"
        family = "QuasarRAT"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {70 2b 3e 2b 43 16 2d 2e 2b 41 72 ?? ?? ?? 70 2b 3d 2b 42 16 2d 0d 2b 40 14 14 2b 3f 74 ?? 00 00 01 2b 3f 08 28 ?? 00 00 0a 16 fe 01 0d 09 2c 0a 08 28}  //weight: 2, accuracy: Low
        $x_1_2 = "ToArray" ascii //weight: 1
        $x_1_3 = "GetCurrentProcess" ascii //weight: 1
        $x_1_4 = "Reverse" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_MSIL_QuasarRAT_G_2147832622_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:MSIL/QuasarRAT.G!MTB"
        threat_id = "2147832622"
        type = "TrojanDownloader"
        platform = "MSIL: .NET intermediate language scripts"
        family = "QuasarRAT"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {06 07 02 07 18 5a 18 6f ?? 00 00 0a 1f 10 28 ?? 00 00 0a 9c 07 17 58 0b 07 06 8e 69 32 e2 06 2a}  //weight: 2, accuracy: Low
        $x_2_2 = {13 06 19 8d ?? 00 00 01 13 ?? 11 ?? 16 28 ?? 00 00 0a 6f ?? 00 00 0a a2 11 ?? 17 7e ?? 00 00 0a a2 11 ?? 18 06 11 06 6f ?? 00 00 0a a2 11 ?? 13 ?? 06 11 04 6f}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_MSIL_QuasarRAT_H_2147834513_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:MSIL/QuasarRAT.H!MTB"
        threat_id = "2147834513"
        type = "TrojanDownloader"
        platform = "MSIL: .NET intermediate language scripts"
        family = "QuasarRAT"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {01 25 d0 01 00 00 04 ?? 2d 0e 26 26 6f ?? 00 00 0a 28 ?? 00 00 06 2b 07 28 ?? 00 00 0a 2b ed 2a}  //weight: 2, accuracy: Low
        $x_2_2 = {07 08 18 5b 02 08 18 6f ?? 00 00 0a 1f 10 28 ?? 00 00 0a 9c 08 18 58 0c 08 06}  //weight: 2, accuracy: Low
        $x_1_3 = "GetResponse" ascii //weight: 1
        $x_1_4 = "ReadToEnd" ascii //weight: 1
        $x_1_5 = "get_Length" ascii //weight: 1
        $x_1_6 = "get_UTF8" ascii //weight: 1
        $x_1_7 = "GetType" ascii //weight: 1
        $x_1_8 = "GetMethod" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_MSIL_QuasarRAT_RDA_2147842200_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:MSIL/QuasarRAT.RDA!MTB"
        threat_id = "2147842200"
        type = "TrojanDownloader"
        platform = "MSIL: .NET intermediate language scripts"
        family = "QuasarRAT"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "c76285f5-60ad-4742-ae2d-e6661316abe1" ascii //weight: 1
        $x_1_2 = "KyqrexPre" ascii //weight: 1
        $x_1_3 = "c4152aae-46e6-480a-801f-5541f3408fd3" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_MSIL_QuasarRAT_I_2147846851_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:MSIL/QuasarRAT.I!MTB"
        threat_id = "2147846851"
        type = "TrojanDownloader"
        platform = "MSIL: .NET intermediate language scripts"
        family = "QuasarRAT"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {02 03 5d 0c 08 0a ?? 13 04 2b ?? 04 05 28 ?? 00 00 0a 04 28 ?? 00 00 0a 05 28 ?? 00 00 0a 28 ?? 00 00 0a 28 ?? 00 00 0a 28 ?? 00 00 0a 0a ?? 13 04 38}  //weight: 2, accuracy: Low
        $x_2_2 = {00 00 1b 11 06 16 16 02 17 8d ?? 00 00 01 25 16 11 06 8c ?? 00 00 01 a2 14 28 ?? 00 00 0a 28 ?? 00 00 0a 16 16 11 09 8c ?? 00 00 01 11 08 8c ?? 00 00 01 18 28 ?? 00 00 06 8c ?? 00 00 01 18 28 ?? 00 00 06 b4 9c}  //weight: 2, accuracy: Low
        $x_2_3 = {00 00 01 14 14 14 28 ?? 00 00 0a 17 8d ?? 00 00 01 25 16 16 8c ?? 00 00 01 a2 14 28}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_MSIL_QuasarRAT_K_2147850694_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:MSIL/QuasarRAT.K!MTB"
        threat_id = "2147850694"
        type = "TrojanDownloader"
        platform = "MSIL: .NET intermediate language scripts"
        family = "QuasarRAT"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {00 00 0a 13 05 38}  //weight: 2, accuracy: High
        $x_2_2 = {11 02 11 07 11 01 02 11 07 18 5a 18}  //weight: 2, accuracy: High
        $x_2_3 = {00 00 0a 18 5b 8d ?? 00 00 01 13 02 38}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_MSIL_QuasarRAT_L_2147850863_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:MSIL/QuasarRAT.L!MTB"
        threat_id = "2147850863"
        type = "TrojanDownloader"
        platform = "MSIL: .NET intermediate language scripts"
        family = "QuasarRAT"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "16"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "U2V0LU1wUHJlZmVyZW5jZSAtRXhjbHVzaW9uUGF0aCAiJGVudjpVU0VSUFJPRklMRVxBcH" wide //weight: 2
        $x_2_2 = "BEYXRhXFJvYW1pbmdcTWljcm9zb2Z0XFdpbmRvd3NcU3RhcnQgTWVudVxQcm9ncmFtc1x" wide //weight: 2
        $x_2_3 = "TdGFydHVw" wide //weight: 2
        $x_2_4 = "SW52b2tlLVdlYlJlcXVlc3QgLXVyaS" wide //weight: 2
        $x_2_5 = "LW91dGZpbGUgIiRlbnY6VVNFUlBST0ZJTEVcQXBwRGF0YVxSb2FtaW5nXE1pY3Jvc29md" wide //weight: 2
        $x_2_6 = "FxXaW5kb3dzXFN0YXJ0IE1lbnVcUHJvZ3JhbXNcU3RhcnR1cFx" wide //weight: 2
        $x_2_7 = "lN0YXJ0LVByb2Nlc3MgIiRlbnY6VVNFUlBST0ZJTEVcQXBwRGF0YVxSb2FtaW5nXE1pY3" wide //weight: 2
        $x_2_8 = "Jvc29mdFxXaW5kb3dzXFN0YXJ0IE1lbnVcUHJvZ3JhbXNcU3RhcnR1cFx" wide //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_MSIL_QuasarRAT_M_2147904150_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:MSIL/QuasarRAT.M!MTB"
        threat_id = "2147904150"
        type = "TrojanDownloader"
        platform = "MSIL: .NET intermediate language scripts"
        family = "QuasarRAT"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "Successfully elevated process privilege" wide //weight: 2
        $x_2_2 = "/Dropper.exe" wide //weight: 2
        $x_2_3 = "C:\\skop\\kurac.exe" wide //weight: 2
        $x_2_4 = "C:\\skop\\mckx.exe" wide //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_MSIL_QuasarRAT_ARA_2147916082_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:MSIL/QuasarRAT.ARA!MTB"
        threat_id = "2147916082"
        type = "TrojanDownloader"
        platform = "MSIL: .NET intermediate language scripts"
        family = "QuasarRAT"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {00 06 02 08 6f ?? ?? ?? 0a 03 08 07 5d 6f ?? ?? ?? 0a 61 d1 6f ?? ?? ?? 0a 26 00 08 17 58 0c 08 02 6f ?? ?? ?? 0a fe 04 0d 09 2d d4}  //weight: 2, accuracy: Low
        $x_2_2 = "DownloadFileAsync" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_MSIL_QuasarRAT_RP_2147922556_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:MSIL/QuasarRAT.RP!MTB"
        threat_id = "2147922556"
        type = "TrojanDownloader"
        platform = "MSIL: .NET intermediate language scripts"
        family = "QuasarRAT"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "11"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {28 0d 00 00 06 28 02 00 00 06 0a 06 6f 04 00 00 06 2a}  //weight: 1, accuracy: High
        $x_10_2 = {09 11 04 a3 ?? ?? 00 01 13 05 11 05 6f ?? ?? 00 0a 72 ?? ?? 00 70 28 ?? ?? 00 0a 39 ?? ?? 00 00 02 11 05 08 28 ?? ?? 00 06 11 04 17 58 13 04 11 04 09 8e 69 32 ca}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_MSIL_QuasarRAT_SS_2147926173_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:MSIL/QuasarRAT.SS!MTB"
        threat_id = "2147926173"
        type = "TrojanDownloader"
        platform = "MSIL: .NET intermediate language scripts"
        family = "QuasarRAT"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "$cc7fad03-816e-432c-9b92-001f2d378498" ascii //weight: 1
        $x_1_2 = "server.Resources.resources" ascii //weight: 1
        $x_1_3 = "FailFast" ascii //weight: 1
        $x_1_4 = "Invoke" ascii //weight: 1
        $x_1_5 = "GetBytes" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_MSIL_QuasarRAT_Q_2147955990_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:MSIL/QuasarRAT.Q!AMTB"
        threat_id = "2147955990"
        type = "TrojanDownloader"
        platform = "MSIL: .NET intermediate language scripts"
        family = "QuasarRAT"
        severity = "Critical"
        info = "AMTB: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_7_1 = {68 74 74 70 [0-1] 3a 2f 2f 34 35 2e 34 33 2e 31 34 33 2e 32 31 32 2f}  //weight: 7, accuracy: Low
        $x_7_2 = {68 74 74 70 [0-1] 3a 2f 2f 74 69 6e 79 75 72 6c 2e 63 6f 6d 2f 33 77 36 70 33 39 65 6d}  //weight: 7, accuracy: Low
        $x_2_3 = "Add-MpPreference -ExclusionPath $" ascii //weight: 2
        $x_1_4 = {5b 53 79 73 74 65 6d 2e 49 4f 2e 50 61 74 68 5d 3a 3a 43 6f 6d 62 69 6e 65 28 24 65 6e 76 3a 41 50 50 44 41 54 41 2c 20 27 [0-26] 27 2c 20 27 [0-20] 2e 65 78 65 27 29}  //weight: 1, accuracy: Low
        $x_1_5 = "Invoke-WebRequest" ascii //weight: 1
        $x_1_6 = "Start-Process -FilePath $outputFile" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_7_*) and 3 of ($x_1_*))) or
            ((1 of ($x_7_*) and 1 of ($x_2_*) and 1 of ($x_1_*))) or
            ((2 of ($x_7_*))) or
            (all of ($x*))
        )
}


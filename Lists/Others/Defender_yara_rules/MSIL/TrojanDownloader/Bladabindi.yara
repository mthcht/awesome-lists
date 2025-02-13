rule TrojanDownloader_MSIL_Bladabindi_A_2147684746_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:MSIL/Bladabindi.A"
        threat_id = "2147684746"
        type = "TrojanDownloader"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Bladabindi"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {1d 28 05 00 00 0a 72 ?? 00 00 70 7e 03 00 00 04 72 ?? 00 00 70 28 06 00 00 0a 17 73 0b 00 00 0a 0b 28 0c 00 00 0a 6f 0d 00 00 0a 28 0e 00 00 0a}  //weight: 2, accuracy: Low
        $x_1_2 = {00 6f 6b 2e 65 78 65 00}  //weight: 1, accuracy: High
        $x_1_3 = "links StartUP hash" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule TrojanDownloader_MSIL_Bladabindi_A_2147684746_1
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:MSIL/Bladabindi.A"
        threat_id = "2147684746"
        type = "TrojanDownloader"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Bladabindi"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {de 00 1d 28 ?? ?? ?? ?? 72 ?? ?? ?? ?? 7e ?? ?? ?? ?? 72 ?? ?? ?? ?? 28}  //weight: 1, accuracy: Low
        $x_1_2 = {11 08 14 72 ?? ?? ?? ?? 16 8d 01 00 00 01 14 14 14 28 ?? ?? ?? ?? 14 72 ?? ?? ?? ?? 18 8d 01 00 00 01}  //weight: 1, accuracy: Low
        $x_1_3 = {00 6f 6b 2e 65 78 65 00}  //weight: 1, accuracy: High
        $x_1_4 = "links StartUP hash" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule TrojanDownloader_MSIL_Bladabindi_A_2147684746_2
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:MSIL/Bladabindi.A"
        threat_id = "2147684746"
        type = "TrojanDownloader"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Bladabindi"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {45 00 6e 00 74 00 72 00 79 00 50 00 6f 00 69 00 6e 00 74 00 ?? ?? 49 00 6e 00 76 00 6f 00 6b 00 65 00 40 00 [0-8] (54 00 72 00 75 00|46 00 61 00 6c 00 73 00) ?? ?? 01 00 00 01 00 00 01 00 00 01 00 00 01 00 00 01 00 00 [0-4] ?? ?? 5c 00 ?? ?? 2e 00 65 00 78 00 65 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_MSIL_Bladabindi_C_2147684956_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:MSIL/Bladabindi.C"
        threat_id = "2147684956"
        type = "TrojanDownloader"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Bladabindi"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "38"
        strings_accuracy = "Low"
    strings:
        $x_16_1 = "\\startup\\WindowsUpdater.exe" wide //weight: 16
        $x_4_2 = ".gulfup.com/" wide //weight: 4
        $x_4_3 = "www5.0zz0.com/2015/01/29/20/742976104.jpg" wide //weight: 4
        $x_2_4 = {2e 00 6a 00 70 00 67 00 ?? ?? 2e 00 4c 00 4f 00 47 00 ?? ?? 2e 00 6a 00 70 00 67 00}  //weight: 2, accuracy: Low
        $x_1_5 = {5c 00 54 00 45 00 4d 00 50 00 5c 00 74 00 6d 00 70 00 29 04 04 00 2e 00 74 00 6d 00 70 00 2e 00 4c 00 4f 00 47 00}  //weight: 1, accuracy: Low
        $x_1_6 = {5c 00 54 00 45 00 4d 00 50 00 5c 00 74 00 6d 00 70 00 29 04 04 00 2e 00 74 00 6d 00 70 00 2e 00 6a 00 70 00 67 00}  //weight: 1, accuracy: Low
        $x_16_7 = {07 1f 10 8d (27|2b|30) 00 00 01 0c 08 16 17 9c 08 17 18 9c 08 18 19 9c 08 19 1a 9c 08 1a 1b 9c 08 1b 1c 9c 08 1c 1d 9c 08 1d 1e}  //weight: 16, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_16_*) and 1 of ($x_4_*) and 2 of ($x_1_*))) or
            ((2 of ($x_16_*) and 1 of ($x_4_*) and 1 of ($x_2_*))) or
            ((2 of ($x_16_*) and 2 of ($x_4_*))) or
            (all of ($x*))
        )
}

rule TrojanDownloader_MSIL_Bladabindi_D_2147685055_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:MSIL/Bladabindi.D"
        threat_id = "2147685055"
        type = "TrojanDownloader"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Bladabindi"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "\\Mr.Zamil\\Zamil\\obj\\Debug\\" ascii //weight: 1
        $x_1_2 = {57 65 62 43 6c 69 65 6e 74 00 44 6f 77 6e 6c 6f 61 64 53 74 72 69 6e 67 00}  //weight: 1, accuracy: High
        $x_1_3 = {3c 4d 6f 64 75 6c 65 3e 00 50 61 74 63 68 2e 65 78 65 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_MSIL_Bladabindi_E_2147686718_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:MSIL/Bladabindi.E"
        threat_id = "2147686718"
        type = "TrojanDownloader"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Bladabindi"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "NJServer.exe" ascii //weight: 1
        $x_1_2 = "DownloadString" ascii //weight: 1
        $x_1_3 = "NJCrypte" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_MSIL_Bladabindi_F_2147689519_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:MSIL/Bladabindi.F"
        threat_id = "2147689519"
        type = "TrojanDownloader"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Bladabindi"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {5c 00 73 00 76 00 63 00 68 00 6f 00 73 00 74 00 2e 00 65 00 78 00 65 00 ?? ?? 4d 00 69 00 63 00 72 00 6f 00 73 00 6f 00 66 00 74 00 ?? ?? 68 00 74 00 74 00 70 00 3a 00 2f 00 2f 00 70 00 61 00 73 00 74 00 65 00 62 00 69 00 6e 00 2e 00 63 00 6f 00 6d 00 2f 00 64 00 6f 00 77 00 6e 00 6c 00 6f 00 61 00 64 00 2e 00 70 00 68 00 70 00 3f 00 69 00 3d 00 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 73 00 6f 00 66 00 74 00 77 00 61 00 72 00 65 00 5c 00 4d 00 69 00 63 00 72 00 6f 00 73 00 6f 00 66 00 74 00 5c 00 57 00 69 00 6e 00 64 00 6f 00 77 00 73 00 5c 00 43 00 75 00 72 00 72 00 65 00 6e 00 74 00 56 00 65 00 72 00 73 00 69 00 6f 00 6e 00 5c 00 52 00 75 00 6e 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_MSIL_Bladabindi_I_2147696974_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:MSIL/Bladabindi.I"
        threat_id = "2147696974"
        type = "TrojanDownloader"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Bladabindi"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "11"
        strings_accuracy = "High"
    strings:
        $x_5_1 = "pastebin.com/download.php?i=" wide //weight: 5
        $x_5_2 = "pepsiKOO" ascii //weight: 5
        $x_1_3 = "\\AVIRA.exe" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_MSIL_Bladabindi_J_2147706786_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:MSIL/Bladabindi.J"
        threat_id = "2147706786"
        type = "TrojanDownloader"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Bladabindi"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {53 74 75 62 2e 65 78 65 00 53 74 75 62 00 6d 73 63 6f 72 6c 69 62}  //weight: 1, accuracy: High
        $x_1_2 = {46 72 6f 6d 42 61 73 65 36 34 53 74 72 69 6e 67 00 41 70 70 44 6f 6d 61 69 6e}  //weight: 1, accuracy: High
        $x_1_3 = {3c 4d 6f 64 75 6c 65 3e 00 50 72 6f 67 72 61 6d 00 4f 62 6a 65 63 74 00 55 72 6c 00 55 72 69 00 57 65 62 43 6c 69 65 6e 74}  //weight: 1, accuracy: High
        $x_1_4 = {44 00 6f 00 77 00 6e 00 6c 00 6f 00 61 00 64 00 53 00 74 00 72 00 69 00 6e 00 67 00 ?? ?? 68 00 74 00 74 00 70 00 3a 00 2f 00 2f 00 70 00 61 00 73 00 74 00 65 00 62 00 69 00 6e 00 2e 00 63 00 6f 00 6d 00 2f 00 72 00 61 00 77 00 2e 00 70 00 68 00 70 00 3f 00 69 00 3d 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_MSIL_Bladabindi_G_2147759768_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:MSIL/Bladabindi.G!MTB"
        threat_id = "2147759768"
        type = "TrojanDownloader"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Bladabindi"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {02 7b 01 00 00 04 02 fe ?? ?? ?? ?? 06 73 ?? ?? ?? 0a 6f ?? ?? ?? 0a 00 72 ?? ?? ?? 70 73 ?? ?? ?? 0a 0a 02 7b ?? ?? ?? 04 06 72 ?? ?? ?? 70 6f ?? ?? ?? 0a}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_MSIL_Bladabindi_G_2147759768_1
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:MSIL/Bladabindi.G!MTB"
        threat_id = "2147759768"
        type = "TrojanDownloader"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Bladabindi"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {73 60 00 00 0a 0a 06 [0-48] 6f 61 00 00 0a 0b 07 [0-48] 28 0c 00 00 06 28 62 00 00 0a 0c 28 63 00 00 0a [0-64] 28 0c 00 00 06 17 17 8d 02 00 00 01 13 06 11 06 16 08 a2 11 06 28 64 00 00 0a}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_MSIL_Bladabindi_B_2147829070_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:MSIL/Bladabindi.B!MTB"
        threat_id = "2147829070"
        type = "TrojanDownloader"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Bladabindi"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {00 00 04 07 08 16 6f ?? 00 00 0a 13 05 12 05 28 ?? 00 00 0a 6f ?? 00 00 0a 00 00 08 17 d6 0c 08 11 04 13 06 11 06}  //weight: 1, accuracy: Low
        $x_1_2 = "Sleep" ascii //weight: 1
        $x_1_3 = "ToCharArray" ascii //weight: 1
        $x_1_4 = "ToArray" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_MSIL_Bladabindi_NX_2147829617_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:MSIL/Bladabindi.NX!MTB"
        threat_id = "2147829617"
        type = "TrojanDownloader"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Bladabindi"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {68 00 00 13 67 00 6e 00 69 00 72 00 74 00 53 00 64 00 61 00 6f 00 00 03 20 00 00 0b 6c 00 6e 00 77 00 6f 00 44 00 00 0f 49 00 49 00 49 00 49 00 49 00 49 00 49}  //weight: 1, accuracy: High
        $x_1_2 = {49 00 00 03 6e 00 00 03 51 00 00 03 76 00 00 03 6f 00 00 03 6b 00 00 11 2b 00 2d 00 2b 00 2d 00 2b 00 2d 00 2b}  //weight: 1, accuracy: High
        $x_1_3 = {0a 26 09 17 d6 0d 09 08 8e 69 32}  //weight: 1, accuracy: High
        $x_1_4 = "daoL" ascii //weight: 1
        $x_1_5 = "moc.nibetsap" ascii //weight: 1
        $x_1_6 = "StrReverse" ascii //weight: 1
        $x_1_7 = "/war/@58EC30A9C23230564C@" ascii //weight: 1
        $x_1_8 = "Replace" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_MSIL_Bladabindi_D_2147834515_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:MSIL/Bladabindi.D!MTB"
        threat_id = "2147834515"
        type = "TrojanDownloader"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Bladabindi"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {04 02 91 20 ?? ?? ?? ff 5f 1f 18 62 0a 06 7e ?? 00 00 04 02 17 58 91 1f 10 62 60 0a 06 7e ?? 00 00 04 02 18 58 91 1e 62 60 0a 06 7e ?? 00 00 04 02 19 58 91 60 0a 02 1a 58 fe}  //weight: 2, accuracy: Low
        $x_2_2 = {06 25 26 6f ?? 00 00 0a 25 26 28 ?? 00 00 06 25 26 20 ?? 00 00 00 28 ?? 00 00 06 25 26 28 ?? ?? 00 06 25 26 02 17 6f ?? 00 00 0a 28 ?? 00 00 06 25 26 20 ?? 00 00 00 28 ?? 00 00 06 25 26 28 ?? ?? 00 06 25 26 28 ?? 00 00 06 25 26 20 ?? ?? 00 00 28 ?? 00 00 06 25 26 28 ?? ?? 00 06 25 26 20 ?? ?? 00 00 28 ?? 00 00 06 25 26 28 ?? 00 00 06 20 ?? ?? 00 00 28 ?? 00 00 0a 28 ?? 00 00 06 25 26 20 ?? 00 00 00 28 ?? 00 00 06 25 26 28 ?? ?? 00 06 25 26 28 ?? 00 00 0a 25 26 26 28 ?? 00 00 06 25 26 20 ?? 00 00 00 28 ?? 00 00 06 25 26 28 ?? ?? 00 06 25 26 28}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_MSIL_Bladabindi_A_2147902679_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:MSIL/Bladabindi.A!MTB"
        threat_id = "2147902679"
        type = "TrojanDownloader"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Bladabindi"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {0a 11 01 20 ?? ?? ?? 82 28 ?? 00 00 06 28 ?? 00 00 0a 28 ?? 00 00 2b 6f ?? 00 00 0a 26 20}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_MSIL_Bladabindi_NITA_2147925786_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:MSIL/Bladabindi.NITA!MTB"
        threat_id = "2147925786"
        type = "TrojanDownloader"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Bladabindi"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {72 d9 01 00 70 28 ?? 00 00 06 72 ca 02 00 70 28 ?? 00 00 0a 28 ?? 00 00 0a 2c 07 16 28 ?? 00 00 0a 2a 72 d9 01 00 70 28 ?? 00 00 06 72 ca 02 00 70 28 ?? 00 00 0a 72 e4 02 00 70 28 ?? 00 00 0a 20 dc 05 00 00 28 ?? 00 00 0a 28 ?? 00 00 06 20 d0 07 00 00 28 ?? 00 00 0a 72 d9 01 00 70 28 ?? 00 00 06 72 b8 02 00 70 28 ?? 00 00 0a 28 ?? 00 00 0a 0a 06 72 f0 02 00 70 72 f4 02 00 70 6f 6a 00 00 0a 0b 07 28 ?? 00 00 0a 0c 20 78 05 00 00 28 ?? 00 00 0a 72 d9 01 00 70 28 ?? 00 00 06 72 f9 01 00 70 28 ?? 00 00 0a 08 28 ?? 00 00 0a 20 b8 0b 00 00 28 ?? 00 00 0a 28 ?? 00 00 06 20 78 05 00 00 28 ?? 00 00 0a 16 28 ?? 00 00 0a 2a}  //weight: 2, accuracy: Low
        $x_1_2 = "DownloadFile" ascii //weight: 1
        $x_1_3 = "WriteAllBytes" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


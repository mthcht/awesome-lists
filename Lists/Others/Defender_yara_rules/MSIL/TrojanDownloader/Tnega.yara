rule TrojanDownloader_MSIL_Tnega_ESS_2147819235_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:MSIL/Tnega.ESS!MTB"
        threat_id = "2147819235"
        type = "TrojanDownloader"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Tnega"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "12"
        strings_accuracy = "High"
    strings:
        $x_10_1 = {16 2d cb 16 fe 02 0c 08 2d d9 2b 03 0b 2b f1 06 6f 13 00 00 0a 28 01 00 00 2b 0d 09 2a 73 15 00 00 0a 38 9d ff ff ff 03 38 a0 ff ff ff 0a 38 aa ff ff ff 0b 2b ab 06 2b ac 07 2b ab 03 2b aa 07 2b a9}  //weight: 10, accuracy: High
        $x_10_2 = {16 fe 02 0c 2b 07 6f 10 00 00 0a 2b eb 08 2d e1 2b 03 0b 2b eb 06 6f 11 00 00 0a 28 01 00 00 2b 0d 2b 03 26 2b bc 09 2a}  //weight: 10, accuracy: High
        $x_10_3 = {07 25 17 59 0b 16 fe 02 0c 2b 03 00 2b f2 08 2d 02 2b 09 2b e0 6f 0c 00 00 0a 2b e1 06 6f 0d 00 00 0a 28 01 00 00 2b 0d 2b 00 09 2a}  //weight: 10, accuracy: High
        $x_1_4 = "GetMethod" ascii //weight: 1
        $x_1_5 = "GetType" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_10_*) and 2 of ($x_1_*))) or
            ((2 of ($x_10_*))) or
            (all of ($x*))
        )
}

rule TrojanDownloader_MSIL_Tnega_XI_2147819561_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:MSIL/Tnega.XI!MTB"
        threat_id = "2147819561"
        type = "TrojanDownloader"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Tnega"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "9"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {61 d2 9c 1f ?? 13 ?? 38 ?? ?? ?? ff 1b 00 08 11 ?? 08 11 ?? 91 11 ?? 11 ?? 09 5d 91}  //weight: 1, accuracy: Low
        $x_1_2 = "edom SOD ni nur eb tonnac margorp sihT" ascii //weight: 1
        $x_1_3 = "WebResponse" ascii //weight: 1
        $x_1_4 = "set_KeySize" ascii //weight: 1
        $x_1_5 = "FromBase64String" ascii //weight: 1
        $x_1_6 = "ToCharArray" ascii //weight: 1
        $x_1_7 = "WebRequest" ascii //weight: 1
        $x_1_8 = "GetManifestResourceStream" ascii //weight: 1
        $x_1_9 = "InvokeMember" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_MSIL_Tnega_PA14_2147819851_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:MSIL/Tnega.PA14!MTB"
        threat_id = "2147819851"
        type = "TrojanDownloader"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Tnega"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Dr4Zaap3qgP4pRB4NWbs9NQuRWalMrMG1AUda1mSG6I5n7u1nNriGo3RF0+Z/lfgeMNzjv46nK1VAIz9QXZ+VfgNxpd" ascii //weight: 1
        $x_1_2 = "tOH82ARnxdnufgODepMgEFCePdFSF4aj26l6HYbXlsnhvCh/NaRIPs+LM/BZtNDSNWyzOq2I4Xdho6ao=" ascii //weight: 1
        $x_1_3 = "lx6kWUt9Qs+ygTelcLeA5lS71PhX1IMP9iSe7zA9C8zUEe+8OF2S73jxMXazBQfLm+TENN7gPIKkc6BCgSyJV" ascii //weight: 1
        $x_1_4 = "+n51hDmYO9yaWP1yiFGAdu/cEvP8ojbpxBqFHzn7xvH" ascii //weight: 1
        $x_1_5 = "lx6kWUt9Qs+ygTelcLeA5lS71PhX1IMP9iSe7zA9C8zUEe+8OF2S73" ascii //weight: 1
        $x_1_6 = "DownloadFile" ascii //weight: 1
        $x_1_7 = "FromBase64String" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_MSIL_Tnega_ABR_2147831438_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:MSIL/Tnega.ABR!MTB"
        threat_id = "2147831438"
        type = "TrojanDownloader"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Tnega"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {0c 07 08 07 6f ?? ?? ?? 0a 1e 5b 6f ?? ?? ?? 0a 6f ?? ?? ?? 0a 07 08 07 6f ?? ?? ?? 0a 1e 5b 6f ?? ?? ?? 0a 6f ?? ?? ?? 0a 2b 07 6f ?? ?? ?? 0a 2b b0 07 17 6f ?? ?? ?? 0a 2b 07 6f ?? ?? ?? 0a 2b 98 06 07 6f ?? ?? ?? 0a 17 73 ?? ?? ?? 0a 0d 09 02 16 02 8e 69 6f ?? ?? ?? 0a de 0a 09 2c 06 09 6f ?? ?? ?? 0a dc 06 6f ?? ?? ?? 0a 13 04 de 14}  //weight: 5, accuracy: Low
        $x_1_2 = "DownloadData" ascii //weight: 1
        $x_1_3 = "MemoryStream" ascii //weight: 1
        $x_1_4 = "CreateDecryptor" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_MSIL_Tnega_ABGR_2147837956_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:MSIL/Tnega.ABGR!MTB"
        threat_id = "2147837956"
        type = "TrojanDownloader"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Tnega"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {06 0c 16 0d 08 12 03 28 ?? ?? ?? 0a 06 02 07 28 ?? ?? ?? 06 6f ?? ?? ?? 0a de 0a 09 2c 06 08 28 ?? ?? ?? 0a dc}  //weight: 1, accuracy: Low
        $x_1_2 = {02 03 18 6f ?? ?? ?? 0a 1f 10 28 ?? ?? ?? 0a 2a}  //weight: 1, accuracy: Low
        $x_1_3 = "Olpjzffwnofonttsofbo" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_MSIL_Tnega_SRPC_2147843337_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:MSIL/Tnega.SRPC!MTB"
        threat_id = "2147843337"
        type = "TrojanDownloader"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Tnega"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {02 73 38 00 00 0a 28 ?? ?? ?? 0a 6f ?? ?? ?? 0a 0a 06 6f ?? ?? ?? 0a 0b 73 26 00 00 0a 0c 73 26 00 00 0a 0d 07 08 6f ?? ?? ?? 0a 08 6f ?? ?? ?? 0a 16 6a 31 33 08 6f ?? ?? ?? 0a 13 04 08 6f ?? ?? ?? 0a 09 11 04 16 11 04 8e 69 6f ?? ?? ?? 0a 09 6f ?? ?? ?? 0a 16 6a 31 0e 11 04 2c 0a 09 6f ?? ?? ?? 0a 13 05}  //weight: 2, accuracy: Low
        $x_1_2 = "185.216.71.120/Fopuetgl.bmp" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_MSIL_Tnega_ABNK_2147845030_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:MSIL/Tnega.ABNK!MTB"
        threat_id = "2147845030"
        type = "TrojanDownloader"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Tnega"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_3_1 = {0a 16 31 07 06 28 ?? ?? ?? 0a 2a 14 2a 31 00 28 ?? ?? ?? 0a 28 ?? ?? ?? 06 6f ?? ?? ?? 0a 72 ?? ?? ?? 70 7e ?? ?? ?? 0a 6f ?? ?? ?? 0a 0a 06 6f}  //weight: 3, accuracy: Low
        $x_1_2 = "Replace" ascii //weight: 1
        $x_1_3 = "FromBase64String" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


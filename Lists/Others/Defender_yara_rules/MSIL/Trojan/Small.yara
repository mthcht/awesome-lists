rule Trojan_MSIL_Small_CK_2147776157_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Small.CK!MTB"
        threat_id = "2147776157"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Small"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "20"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {2d 25 1f 10 d0 [0-4] 28 [0-4] d0 [0-4] 28 [0-4] 28 [0-4] 28 [0-4] 80 [0-4] 7e [0-4] 7b [0-4] 7e [0-4] 18 8d [0-4] 25 16 12 02 28 [0-4] a2 25 17 07 a2 28 [0-14] 26 08 17 58 0c 08 07}  //weight: 10, accuracy: Low
        $x_2_2 = "DownloadData" ascii //weight: 2
        $x_2_3 = "GetProcAddress" ascii //weight: 2
        $x_2_4 = "AddressOfEntryPoint" ascii //weight: 2
        $x_2_5 = "FromBase64String" ascii //weight: 2
        $x_2_6 = "SizeOfRawData" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Small_AT_2147779309_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Small.AT!MTB"
        threat_id = "2147779309"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Small"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "21"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {0a 72 1b 03 19 70 02 7b 01 ?? ?? 04 72 1f 03 19 70 28 ?? ?? ?? 0a 28 1a ?? ?? 0a 26 2a 86 28 12 ?? ?? 0a 72 1b 03 19 70 02 7b 02 ?? ?? 04 72 1f 03 19 70 28 13 ?? ?? 0a 28 1a ?? ?? 0a 26 2a}  //weight: 10, accuracy: Low
        $x_5_2 = "H4sIAAAAAAAEAO0523biuLIflIeY23R42A8l37DBBBl8fcM2EWBz6QAx5ut3lWwCpNOzzuyzzjr7obVmUkiue5WkKvXM" ascii //weight: 5
        $x_5_3 = {63 66 6b 62 d8 b1 d9 82 d9 8a d8 ae 75 76 67 75 6a d8 af d9 85 d8 b1 d8 b9}  //weight: 5, accuracy: High
        $x_5_4 = {69 d9 88 74 62 65 6c 79 67 70 73 d9 84}  //weight: 5, accuracy: High
        $x_3_5 = "GetTempPath" ascii //weight: 3
        $x_3_6 = "FromBase64String" ascii //weight: 3
    condition:
        (filesize < 20MB) and
        (
            ((3 of ($x_5_*) and 2 of ($x_3_*))) or
            ((1 of ($x_10_*) and 1 of ($x_5_*) and 2 of ($x_3_*))) or
            ((1 of ($x_10_*) and 2 of ($x_5_*) and 1 of ($x_3_*))) or
            ((1 of ($x_10_*) and 3 of ($x_5_*))) or
            (all of ($x*))
        )
}

rule Trojan_MSIL_Small_CHR_2147780444_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Small.CHR!MTB"
        threat_id = "2147780444"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Small"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "15"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {0a 0a 06 72 55 ?? ?? 70 6f ?? ?? ?? 0a 0b 07 0c 72 ?? ?? ?? 70 0d 00 73 ?? ?? ?? 0a 13 04}  //weight: 10, accuracy: Low
        $x_3_2 = "CreateDirectory" ascii //weight: 3
        $x_3_3 = "\\MyTemp\\Setup" ascii //weight: 3
        $x_3_4 = "WebClient" ascii //weight: 3
        $x_3_5 = "DownloadString" ascii //weight: 3
        $x_3_6 = "Z2k/Server" ascii //weight: 3
    condition:
        (filesize < 20MB) and
        (
            ((5 of ($x_3_*))) or
            ((1 of ($x_10_*) and 2 of ($x_3_*))) or
            (all of ($x*))
        )
}

rule Trojan_MSIL_Small_GU_2147781328_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Small.GU!MTB"
        threat_id = "2147781328"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Small"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "23"
        strings_accuracy = "High"
    strings:
        $x_3_1 = "rNLi3xTsoLr5VEBmEo7QXiejuzO22BR8TE8vDcKXcJxvvXWNl4fUbsq7EhIM7ONMSRplLmi" ascii //weight: 3
        $x_3_2 = "JrxaLsowrrYVPKFE0F" ascii //weight: 3
        $x_3_3 = "pRcoaP8zpN22RD1yv79fOZLL7Hs5tZx5p79UIa032gyyiWxFx9MHktxMLyY" ascii //weight: 3
        $x_3_4 = "hXeUOLDc69thwnjQNckwzb5hPWhYBX7CAjoEr" ascii //weight: 3
        $x_3_5 = "ktq7yDexyy5iI790I" ascii //weight: 3
        $x_2_6 = "GetTempPath" ascii //weight: 2
        $x_2_7 = "FromBase64String" ascii //weight: 2
        $x_2_8 = "GZipStream" ascii //weight: 2
        $x_2_9 = "MemoryStream" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Small_FAC_2147781333_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Small.FAC!MTB"
        threat_id = "2147781333"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Small"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "30"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {07 08 9a 0a 06 28 ?? ?? ?? 06 20 c4 09 00 00 28 ?? ?? ?? 0a de 03}  //weight: 10, accuracy: Low
        $x_4_2 = "ListURLS" ascii //weight: 4
        $x_4_3 = "Payload" ascii //weight: 4
        $x_4_4 = "FetchFiles" ascii //weight: 4
        $x_4_5 = "Intrnet" ascii //weight: 4
        $x_4_6 = "DownloadData" ascii //weight: 4
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Small_GB_2147787405_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Small.GB!MTB"
        threat_id = "2147787405"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Small"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {28 1c 00 00 0a 20 08 00 00 00 38 68 ff ff ff 28 13 00 00 0a 20 08 00 00 00 28 1d 00 00 06 6f 14 00 00 0a 3a 08 ff ff ff 20 00 00 00 00 fe 0e 02 00 28 04 00 00 06 3a 38 ff ff ff 07 73 1d 00 00 0a 25 16 6f 1e 00 00 0a 6f 1f 00 00 0a 20 06 00 00 00 fe 0e 02 00 28 04 00 00 06 39 b0 fe ff ff 38 0e ff ff ff}  //weight: 1, accuracy: High
        $x_1_2 = "Bitcoin_Grabber" ascii //weight: 1
        $x_1_3 = "o5x0R6uFfZQhrE29Mc" ascii //weight: 1
        $x_1_4 = "Rw3n6EZIW3XXSwRLNN" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Small_BZ_2147793430_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Small.BZ!MTB"
        threat_id = "2147793430"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Small"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "MemReduc\\DriveUpdate\\obj\\Release\\WindowsSearch.App.pdb" ascii //weight: 1
        $x_1_2 = "https://cdn.discordapp.com/attachments/8" wide //weight: 1
        $x_1_3 = "DownloadData" ascii //weight: 1
        $x_1_4 = "URLZONE_INTRANET" ascii //weight: 1
        $x_1_5 = "SystemUWPLauncher" ascii //weight: 1
        $x_1_6 = "Intrnet" ascii //weight: 1
        $x_1_7 = "FetchFiles" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Small_CPP_2147798651_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Small.CPP!MTB"
        threat_id = "2147798651"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Small"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "WindowsFormsApp6" ascii //weight: 1
        $x_1_2 = "5481B190213E555720F1ACBE99181DB7D20FD3A1E8CC64676E00EB0CA571C7AA" ascii //weight: 1
        $x_1_3 = "$c4cb9b1e-9c29-4a40-ba7b-60a3ec18d903" ascii //weight: 1
        $x_1_4 = "https://cdn.discordapp.com/attachments/875419662094045264/891604" wide //weight: 1
        $x_1_5 = "C:\\ProgramData\\Stub.exe" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Small_FB_2147808806_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Small.FB!MTB"
        threat_id = "2147808806"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Small"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "16"
        strings_accuracy = "High"
    strings:
        $x_10_1 = {20 00 ca 9a 3b 0d 16 13 04 2b 50 00 1f 2d 28 1a 00 00 0a 00 16 13 05 2b 2e 00 07 11 05 06 08 06 6f 1b 00 00 0a 6f 1c 00 00 0a 6f 1d 00 00 0a 9d 07 73 1e 00 00 0a 13 06 11 06 28 1f 00 00 0a 00 00 11 05 17 58 13 05 11 05 07 8e 69 fe 04 13 07 11 07 2d c5}  //weight: 10, accuracy: High
        $x_3_2 = "Loader" ascii //weight: 3
        $x_3_3 = "Cheat" ascii //weight: 3
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Small_EC_2147838537_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Small.EC!MTB"
        threat_id = "2147838537"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Small"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "VmtkR2VrOVhWbms9" ascii //weight: 1
        $x_1_2 = "49f770658c6b27a7" ascii //weight: 1
        $x_1_3 = "payload" ascii //weight: 1
        $x_1_4 = "RijndaelManaged" ascii //weight: 1
        $x_1_5 = "SymmetricAlgorithm" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Small_EC_2147838537_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Small.EC!MTB"
        threat_id = "2147838537"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Small"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "/Common/sncnxwutdhwx.aspx" ascii //weight: 1
        $x_1_2 = "8edb23160d1571a0" ascii //weight: 1
        $x_1_3 = "/Common/uyisghgofwff.aspx" ascii //weight: 1
        $x_1_4 = "HttpServerUtility" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Small_EC_2147838537_2
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Small.EC!MTB"
        threat_id = "2147838537"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Small"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "11"
        strings_accuracy = "High"
    strings:
        $x_8_1 = {8e 69 5d 91 61 d2 9c 00 07 17 58 0b 07 02 8e 69 fe 04 0c 08 2d cd}  //weight: 8, accuracy: High
        $x_1_2 = "[+] Successfully disabled AMSI!" ascii //weight: 1
        $x_1_3 = "[+] Successfully unhooked ETW!" ascii //weight: 1
        $x_1_4 = "[+] URL/PATH" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Small_EC_2147838537_3
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Small.EC!MTB"
        threat_id = "2147838537"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Small"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Common/odsfdrommeck.aspx" ascii //weight: 1
        $x_1_2 = "8edb23160d1571a0" ascii //weight: 1
        $x_1_3 = "Common/etgapabbtgbe.aspx" ascii //weight: 1
        $x_1_4 = "Common/dbbrngmyieew.aspx" ascii //weight: 1
        $x_1_5 = "HttpServerUtility" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Small_EC_2147838537_4
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Small.EC!MTB"
        threat_id = "2147838537"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Small"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "PHXLegacy.exe" wide //weight: 1
        $x_1_2 = "dCArICIgZmlsZXMuIikNCldyaXRlLUhvc3QgKCRzdG9wdGltZSAtICRzdGFydHRpbWUp" wide //weight: 1
        $x_1_3 = "FromBase64String" ascii //weight: 1
        $x_1_4 = "DllImportAttribute" ascii //weight: 1
        $x_1_5 = "System.Management.Automation.Host" ascii //weight: 1
        $x_1_6 = "PSHostUserInterface" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Small_EA_2147842760_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Small.EA!MTB"
        threat_id = "2147842760"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Small"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_5_1 = {72 f9 01 00 70 0a 73 34 00 00 0a 0b 73 29 00 00 0a 25 72 e9 00 00 70 6f 2a 00 00 0a 00 25 72 a0 03 00 70 06 72 b6 03 00 70}  //weight: 5, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Small_PSKW_2147845494_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Small.PSKW!MTB"
        threat_id = "2147845494"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Small"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {6f 57 00 00 0a 28 ?? ?? ?? 0a 18 16 15 28 ?? ?? ?? 0a 26 28 06 00 00 06 6f ?? ?? ?? 0a 72 ee 01 00 70 72 32 02 00 70 6f ?? ?? ?? 0a 00 28 06 00 00 06 6f 5a 00 00 0a 72 64 02 00 70 72 a4 02 00 70 6f ?? ?? ?? 0a 00 00 2a}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Small_EM_2147847284_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Small.EM!MTB"
        threat_id = "2147847284"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Small"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "TWljcm9zb2Z0QXBpJQ==" wide //weight: 1
        $x_1_2 = "TWljcm9zb2Z0QXBpJA==" wide //weight: 1
        $x_1_3 = "ec632fd9-1694-4f4a-9bff-f20600e37981" ascii //weight: 1
        $x_1_4 = "ZWM2MzJmZDktMTY5NC00ZjRhLTliZmYtZjIwNjAwZTM3OTgx" ascii //weight: 1
        $x_1_5 = "MicrosoftApi.exe" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Small_CXRM_2147847847_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Small.CXRM!MTB"
        threat_id = "2147847847"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Small"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {28 12 00 00 06 0a 28 20 00 00 0a 06 6f 21 00 00 0a 28 11 00 00 06 75 02 00 00 1b 0b 07 16 07 8e 69 28 ?? 00 00 0a 07 2a}  //weight: 1, accuracy: Low
        $x_1_2 = "Owtwhzdlif" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Small_SPWR_2147889141_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Small.SPWR!MTB"
        threat_id = "2147889141"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Small"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_4_1 = {02 7b 01 00 00 04 02 7b 0c 00 00 04 02 7b 0b 00 00 04 28 ?? ?? ?? 0a 6f ?? ?? ?? 0a 02 02 7b 01 00 00 04 6f ?? ?? ?? 0a 7d 02 00 00 04 02 02 7b 02 00 00 04 73 1d 00 00 0a 7d 04 00 00 04 02 02 7b 02 00 00 04 73 1e 00 00 0a 7d 03 00 00 04 02 02}  //weight: 4, accuracy: Low
        $x_1_2 = "discosDuros" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Small_PTDW_2147898911_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Small.PTDW!MTB"
        threat_id = "2147898911"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Small"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {de 91 f9 97 47 77 5a 19 3b 90 c6 7b 37 6a 66 df c9 78}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Small_RKAA_2147915865_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Small.RKAA!MTB"
        threat_id = "2147915865"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Small"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_3_1 = {0a 08 17 9a 28 ?? 00 00 0a 00 28 ?? 00 00 0a 72 ?? 00 00 70 28 ?? 00 00 0a 28 ?? 00 00 0a 26 28 ?? 00 00 06 6f ?? 00 00 0a 00 2b 55 73 ?? 00 00 0a 13 08 11 08 72 ?? 00 00 70 6f ?? 00 00 0a 00 11 08 17 6f ?? 00 00 0a 00 11 08 72 ?? 00 00 70 08 17 9a 72 ?? 00 00 70 28 ?? 00 00 0a 6f ?? 00 00 0a 00 11 08 28 ?? 00 00 0a 26}  //weight: 3, accuracy: Low
        $x_2_2 = {0a 13 05 11 05 28 ?? 00 00 06 6f ?? 00 00 0a 74 ?? 00 00 1b 13 06 28 ?? 00 00 0a 72 ?? 00 00 70 7e ?? 00 00 04 28 ?? 00 00 0a 28 ?? 00 00 0a 17 73 ?? 00 00 0a 13 07 11 07 11 06 16 11 06 8e 69 6f ?? 00 00 0a 00 11 07}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Small_SK_2147918468_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Small.SK!MTB"
        threat_id = "2147918468"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Small"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "FakeFunctionDriver" ascii //weight: 1
        $x_1_2 = "DisableRealTimeProtection" ascii //weight: 1
        $x_1_3 = "AntiVMCheck" ascii //weight: 1
        $x_1_4 = "DisableDefenderServices" ascii //weight: 1
        $x_1_5 = "INFARCTED LAUNCHER 2K24" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}


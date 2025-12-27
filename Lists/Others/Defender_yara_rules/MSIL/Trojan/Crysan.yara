rule Trojan_MSIL_Crysan_A_2147759417_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Crysan.A!MTB"
        threat_id = "2147759417"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Crysan"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {27 09 11 09 2b 09 2d 09 18 09 20 09 2f 09 0f 09 2b 09 1b 09 18 09 2b 09 2f 09 01}  //weight: 1, accuracy: High
        $x_1_2 = "*/*G*/*e*/*t*/*M*/*e*/*t*/*h*/*o*/*d" ascii //weight: 1
        $x_1_3 = "1010101092 1010101127 1010101120 1010101090 1010101079 1010101056 1010101092 1010101127 1010101120 1010101090" ascii //weight: 1
        $x_1_4 = "1010101097 1010101091 1010101076 1010101089 1010101098 1010101076 1010101093 1010101079 1010101089" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Crysan_2147761753_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Crysan!MTB"
        threat_id = "2147761753"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Crysan"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {0a 06 0b 16 8d 4c ?? ?? 01 0c 07 7e 36 ?? ?? 04 25 2d 17 26 7e 35 ?? ?? 04 fe 06 ?? ?? ?? 06 73 5f ?? ?? 0a 25 80 36 ?? ?? 04 28 01 ?? ?? 2b 28 02 ?? ?? 2b 0c}  //weight: 5, accuracy: Low
        $x_1_2 = "ToArray" ascii //weight: 1
        $x_1_3 = "get_Assembly" ascii //weight: 1
        $x_1_4 = "DirectoryEntry" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Crysan_2147761753_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Crysan!MTB"
        threat_id = "2147761753"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Crysan"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_6_1 = {07 16 fe 01 0d 09 2c 14 06 07 07 b4 9c 06 07 17 d6 03 28 b7 ?? ?? 0a b4 9c 00 2b 18 07 17 fe 02 13 04 11 04 2c 0e 06 07 03 1f 63 d6 28 b7 ?? ?? 0a b4 9c}  //weight: 6, accuracy: Low
        $x_1_2 = "GetResourceString" ascii //weight: 1
        $x_1_3 = "ToString" ascii //weight: 1
        $x_1_4 = "GetDomain" ascii //weight: 1
        $x_1_5 = "ToInteger" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Crysan_PAA_2147776892_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Crysan.PAA!MTB"
        threat_id = "2147776892"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Crysan"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "35"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "sgdafjhdfsajdgsjafgdksagfeufgewqtfduyatssfasaaaa" ascii //weight: 10
        $x_10_2 = "FromHtml" ascii //weight: 10
        $x_10_3 = "ToHtml" ascii //weight: 10
        $x_1_4 = "Dispose__Instance__" ascii //weight: 1
        $x_1_5 = "Create__Instance__" ascii //weight: 1
        $x_1_6 = "get_WhiteSmoke" ascii //weight: 1
        $x_1_7 = "get_Fuchsia" ascii //weight: 1
        $x_1_8 = "get_KeyCode" ascii //weight: 1
        $x_1_9 = "HuraModule" ascii //weight: 1
        $x_1_10 = "LateCall" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((3 of ($x_10_*) and 5 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Trojan_MSIL_Crysan_BXJ_2147787299_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Crysan.BXJ!MTB"
        threat_id = "2147787299"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Crysan"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {4a 00 72 01 00 00 70 72 0d 00 00 70 28 14 00 00 0a 26 2a}  //weight: 1, accuracy: High
        $x_1_2 = ".us.archive.org" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Crysan_IWO_2147796835_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Crysan.IWO!MTB"
        threat_id = "2147796835"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Crysan"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "11"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "StudentCalculate.Resources" wide //weight: 1
        $x_1_2 = "BIG_DISCORD_LINK_STRING" wide //weight: 1
        $x_1_3 = "membertoinvoke" wide //weight: 1
        $x_1_4 = "makmal yang diperlukan" wide //weight: 1
        $x_1_5 = "BtnCalculate" wide //weight: 1
        $x_1_6 = "lblJumlahMakmal" wide //weight: 1
        $x_1_7 = "JumlahPelajar" wide //weight: 1
        $x_1_8 = "NR_wkdoqwkdoqwkdq" ascii //weight: 1
        $x_1_9 = "set_Expect100Continue" ascii //weight: 1
        $x_1_10 = "NR_Bostoroth" ascii //weight: 1
        $x_1_11 = "get_lblJumlahMakmal" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Crysan_IF_2147797052_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Crysan.IF!MTB"
        threat_id = "2147797052"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Crysan"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "XRavNbdkMTpIF Copyright" wide //weight: 1
        $x_1_2 = "$8A6C08CD-6A6A-7636-45DA-E2FA6DAF31E6" ascii //weight: 1
        $x_1_3 = "UEFHSE5DUiQ=" wide //weight: 1
        $x_1_4 = "DcRat\\Binaries\\Release\\CryptoObfuscator_Output\\PAGHNCR.pdb" ascii //weight: 1
        $x_1_5 = "zwmHSTEByMnHu" ascii //weight: 1
        $x_1_6 = "aNQMBOGknsMCb" ascii //weight: 1
        $x_1_7 = "mDXfsUApQbcbo" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Crysan_AD_2147797737_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Crysan.AD!MTB"
        threat_id = "2147797737"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Crysan"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "21"
        strings_accuracy = "High"
    strings:
        $x_3_1 = "Q2xpZW50XyQ=" ascii //weight: 3
        $x_3_2 = "225.22.26.35" ascii //weight: 3
        $x_3_3 = "Assem" ascii //weight: 3
        $x_3_4 = "CheckHostName" ascii //weight: 3
        $x_3_5 = "get_OSFullName" ascii //weight: 3
        $x_3_6 = "DownloadString" ascii //weight: 3
        $x_3_7 = "set_UseShellExecute" ascii //weight: 3
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Crysan_SIBA_2147807754_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Crysan.SIBA!MTB"
        threat_id = "2147807754"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Crysan"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {9d 1d 8d 27 ?? ?? ?? fe 0e ?? ?? [0-80] fe 0c 01 1c 1f 6d 9d [0-96] fe 0c 01 1b 1f 61 9d [0-96] fe 0c 01 1a 1f 72 9d [0-96] fe 0c 01 19 1f 67 9d [0-96] fe 0c 01 18 1f 6f 9d [0-96] fe 0c 01 17 1f 72 9d [0-96] fe 0c 01 16 1f 50 9d}  //weight: 1, accuracy: Low
        $x_1_2 = {9d 1a 8d 27 ?? ?? ?? fe 0e ?? ?? [0-80] fe 0c 01 19 1f 65 9d [0-80] fe 0c 01 18 1f 6d 9d [0-80] fe 0c 01 17 1f 61 9d [0-80] fe 0c 01 16 1f 4e 9d}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Crysan_BN_2147809841_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Crysan.BN!MTB"
        threat_id = "2147809841"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Crysan"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Antivirus" ascii //weight: 1
        $x_1_2 = "Anti_Process" ascii //weight: 1
        $x_1_3 = "Anti_Analysis" ascii //weight: 1
        $x_1_4 = "DecodeFromBytes" ascii //weight: 1
        $x_1_5 = "FromBase64String" ascii //weight: 1
        $x_1_6 = "DebuggerInactive" ascii //weight: 1
        $x_1_7 = "_Qr0pxDOL0D5H8BGzHHaMyWWbgnG" ascii //weight: 1
        $x_1_8 = "VirusInfected" ascii //weight: 1
        $x_1_9 = "VirusDeleted" ascii //weight: 1
        $x_1_10 = "DecodeFromFile" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Crysan_FHOR_2147811645_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Crysan.FHOR!MTB"
        threat_id = "2147811645"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Crysan"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {14 0a 1e 8d 83 00 00 01 25 d0 d5 00 00 04 28 ?? ?? ?? 0a 0b 73 c9 00 00 0a 0c 00 73 ca 00 00 0a 0d 00 09 20 00 01 00 00 6f ?? ?? ?? 0a 00 09 20 80 00 00 00 6f ?? ?? ?? 0a 00 28 ?? ?? ?? 0a 72 95 0a 00 70 6f ?? ?? ?? 0a 13 04 11 04 07 20 e8 03 00 00 73 cf 00 00 0a 13 05 09 11 05 09 6f ?? ?? ?? 0a 1e 5b 6f ?? ?? ?? 0a 6f ?? ?? ?? 0a 00 09 11 05 09 6f ?? ?? ?? 0a 1e 5b 6f ?? ?? ?? 0a 6f ?? ?? ?? 0a 00 09 17 6f ?? ?? ?? 0a 00 08 09 6f ?? ?? ?? 0a 17 73 d7 00 00 0a 13 06 00 11 06 03 16 03 8e 69 6f ?? ?? ?? 0a 00 11 06 6f ?? ?? ?? 0a 00 00 de 0d 11 06 2c 08 11 06 6f ?? ?? ?? 0a 00 dc 08 6f ?? ?? ?? 0a 0a 00 de 0b 09 2c 07 09 6f ?? ?? ?? 0a 00 dc 00 de 0b 08 2c 07 08 6f ?? ?? ?? 0a 00 dc 06 13 07 2b 00 11 07 2a}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Crysan_GHOR_2147811646_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Crysan.GHOR!MTB"
        threat_id = "2147811646"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Crysan"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {11 05 17 58 20 00 01 00 00 5d 13 05 11 06 09 11 05 94 58 20 00 01 00 00 5d 13 06 09 11 05 94 13 0d 09 11 05 09 11 06 94 9e 09 11 06 11 0d 9e 09 09 11 05 94 09 11 06 94 58 20 00 01 00 00 5d 94 13 0e 11 07 11 0c 02 11 0c 91 11 0e 61 28 ?? ?? ?? 0a 9c 11 0c 17 58 13 0c 11 0c 02 8e 69 32 a0}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Crysan_PHOR_2147811647_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Crysan.PHOR!MTB"
        threat_id = "2147811647"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Crysan"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {73 4f 00 00 0a 0b 28 ?? ?? ?? 06 0c 16 0d 2b 6f ?? ?? ?? 04 2b 55 00 08 09 11 04 6f ?? ?? ?? 0a 13 05 d0 4f 00 00 01 28 ?? ?? ?? 0a 72 39 02 00 70 28 ?? ?? ?? 0a 20 00 01 00 00 14 14 17 8d 18 00 00 01 25 16 11 05 8c 26 00 00 01 a2 28 ?? ?? ?? 0a a5 46 00 00 01 13 06 07 09 11 06 d2 6f ?? ?? ?? 0a 00 00 11 04 17 58 13 04 11 04 17 fe 04 13 07 11 07 2d a0 06 17 58 0a 00 09 17 58 0d 09 20 00 56 00 00 fe 04 13 08 11 08 2d 83}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Crysan_KTR_2147812856_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Crysan.KTR!MTB"
        threat_id = "2147812856"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Crysan"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {8d 24 00 00 01 25 d0 05 00 00 04 28 ?? ?? ?? 0a 0a 06 0b 16 8d 28 ?? ?? ?? 0c 07 7e 07 00 00 04 25 2d 17 26 7e 06 00 00 04 fe 06 0f 00 00 06 73 1c 00 00 0a 25 80 07 00 00 04 28 ?? ?? ?? 2b 28 ?? ?? ?? 2b 0c 00 d0 2b 00 00 01 28 ?? ?? ?? 0a 28 ?? ?? ?? 0a 08 6f ?? ?? ?? 0a 6f ?? ?? ?? 0a 28 ?? ?? ?? 0a 0d 09 14 6f ?? ?? ?? 0a 26 2a}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Crysan_Hadyn_2147813526_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Crysan.Hadyn!MTB"
        threat_id = "2147813526"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Crysan"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "20"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "Reverse" ascii //weight: 2
        $x_2_2 = "GetString" ascii //weight: 2
        $x_2_3 = "GetType" ascii //weight: 2
        $x_2_4 = "XUxIlAwxlPDgbbt" ascii //weight: 2
        $x_2_5 = "ToCharArray" ascii //weight: 2
        $x_2_6 = "DownloadData" ascii //weight: 2
        $x_2_7 = "InvokeMember" ascii //weight: 2
        $x_2_8 = "OSOZvDsfxzQNmkeQdCosv" ascii //weight: 2
        $x_4_9 = "laurentprotector.com" ascii //weight: 4
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Crysan_KLS_2147813726_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Crysan.KLS!MTB"
        threat_id = "2147813726"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Crysan"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_4_1 = {d0 21 00 00 01 28 ?? ?? ?? 0a 72 01 00 00 70 17 8d 14 00 00 01 25 16 d0 21 00 00 01 28 ?? ?? ?? 0a a2 28 ?? ?? ?? 0a 14 17 8d 10 00 00 01 25 16 02 50 a2 6f ?? ?? ?? 0a 26 2a}  //weight: 4, accuracy: Low
        $x_2_2 = "GetExportedTypes" ascii //weight: 2
        $x_2_3 = "GetAssemblies" ascii //weight: 2
        $x_2_4 = "GetMethods" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Crysan_KKG_2147814755_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Crysan.KKG!MTB"
        threat_id = "2147814755"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Crysan"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "14"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "abdo" ascii //weight: 2
        $x_2_2 = "rrrrrrrrrrrrweerw" ascii //weight: 2
        $x_2_3 = "ewewweqewqeqw" ascii //weight: 2
        $x_2_4 = "DownloadFile" ascii //weight: 2
        $x_2_5 = "FromBase64String" ascii //weight: 2
        $x_2_6 = {00 65 65 65 65 65 65 65 65 65 65 65 65 65 65 65 65 00}  //weight: 2, accuracy: High
        $x_2_7 = {00 77 77 77 77 77 77 77 77 77 77 77 77 77 00}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Crysan_SWT_2147814760_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Crysan.SWT!MTB"
        threat_id = "2147814760"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Crysan"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "15"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {54 00 56 00 71 00 51 00 1d 09 1d 09 4d 00 1d 09 1d 09 1d 09 1d 09}  //weight: 1, accuracy: High
        $x_1_2 = {46 00 68 00 4d 00 45 00 4b 00 30 00 63 00 1d 09}  //weight: 1, accuracy: High
        $x_1_3 = {1d 09 69 00 75 00 38 00 62 00 33 00 30 00 1d 09 1d 09}  //weight: 1, accuracy: High
        $x_1_4 = {39 00 43 00 69 00 52 00 1d 09 1d 09 1d 09 47 00}  //weight: 1, accuracy: High
        $x_1_5 = {48 00 77 00 1d 09 1d 09 1d 09 1d 09 4d 00 1d 09 1d 09}  //weight: 1, accuracy: High
        $x_2_6 = "GetExportedTypes" ascii //weight: 2
        $x_2_7 = "GetType" ascii //weight: 2
        $x_2_8 = "IDeferred" ascii //weight: 2
        $x_2_9 = "InvokeMember" ascii //weight: 2
        $x_2_10 = "FromBase64String" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Crysan_DWT_2147814761_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Crysan.DWT!MTB"
        threat_id = "2147814761"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Crysan"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "9"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "iamkingg" ascii //weight: 1
        $x_1_2 = "InvokeMember" ascii //weight: 1
        $x_1_3 = "GetString" ascii //weight: 1
        $x_1_4 = "yarram" ascii //weight: 1
        $x_1_5 = "DownloadData" ascii //weight: 1
        $x_1_6 = "WebClient" ascii //weight: 1
        $x_1_7 = "laurentprotector.com/binler/" wide //weight: 1
        $x_1_8 = "NyWNsKUOUIVZzBN" wide //weight: 1
        $x_1_9 = "PRmobhOKZEZKBvX.LuUncGzqEwEpNsj" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Crysan_LWT_2147814762_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Crysan.LWT!MTB"
        threat_id = "2147814762"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Crysan"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "35"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "InvokeMember" ascii //weight: 1
        $x_1_2 = "GetType" ascii //weight: 1
        $x_1_3 = "GetString" ascii //weight: 1
        $x_1_4 = "DownloadData" ascii //weight: 1
        $x_1_5 = "WebClient" ascii //weight: 1
        $x_20_6 = "laurentprotector.com" ascii //weight: 20
        $x_10_7 = "NnQFqsOEUtkezvIEcLpfa.gcuQgMABINcyggDMBxPqv" ascii //weight: 10
        $x_10_8 = "OSOZvDsfxzQNmkeQdCosv" ascii //weight: 10
        $x_10_9 = "Ge.ntfQURVxKEvCoFyPNoOZETutIQC" ascii //weight: 10
        $x_10_10 = "ekYdODMgJCaTPBCtPDNrDaWLJWo" ascii //weight: 10
        $x_10_11 = "Voizs" ascii //weight: 10
        $x_10_12 = "Cabriolet" ascii //weight: 10
    condition:
        (filesize < 20MB) and
        (
            ((3 of ($x_10_*) and 5 of ($x_1_*))) or
            ((4 of ($x_10_*))) or
            ((1 of ($x_20_*) and 1 of ($x_10_*) and 5 of ($x_1_*))) or
            ((1 of ($x_20_*) and 2 of ($x_10_*))) or
            (all of ($x*))
        )
}

rule Trojan_MSIL_Crysan_IZD_2147814765_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Crysan.IZD!MTB"
        threat_id = "2147814765"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Crysan"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {14 0a 1e 8d 25 00 00 01 25 d0 05 00 00 04 28 ?? ?? ?? 0a 0b 73 16 00 00 0a 0c 00 73 17 00 00 0a 0d 00 09 20 00 01 00 00 6f ?? ?? ?? 0a 00 09 20 80 00 00 00 6f ?? ?? ?? 0a 00 28 ?? ?? ?? 0a 72 01 00 00 70 6f ?? ?? ?? 0a 13 04 11 04 07 20 e8 03 00 00 73 1c 00 00 0a 13 05 09 11 05 09 6f ?? ?? ?? 0a 1e 5b 6f ?? ?? ?? 0a 6f ?? ?? ?? 0a 00 09 11 05 09 6f ?? ?? ?? 0a 1e 5b 6f ?? ?? ?? 0a 6f ?? ?? ?? 0a 00 09 17 6f ?? ?? ?? 0a 00 08 09 6f ?? ?? ?? 0a 17 73 24 00 00 0a 13 06 00 11 06 03 16 03 8e 69 6f ?? ?? ?? 0a 00 11 06 6f ?? ?? ?? 0a 00 00 de 0d}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Crysan_SLB_2147814770_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Crysan.SLB!MTB"
        threat_id = "2147814770"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Crysan"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "9"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "FromBase64String" ascii //weight: 1
        $x_1_2 = "Invoke" ascii //weight: 1
        $x_1_3 = "ToString" ascii //weight: 1
        $x_1_4 = "WindowsApps.Resources.resources" ascii //weight: 1
        $x_5_5 = "pastebin.com/raw/f8L57FN1" ascii //weight: 5
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Crysan_AEND_2147815745_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Crysan.AEND!MTB"
        threat_id = "2147815745"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Crysan"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "DownloadData" ascii //weight: 1
        $x_1_2 = "WebClient" ascii //weight: 1
        $x_1_3 = "laurentprotector.com" wide //weight: 1
        $x_1_4 = "InvokeMember" ascii //weight: 1
        $x_1_5 = "GetType" ascii //weight: 1
        $x_1_6 = "DiffLevel.BzsteuMyBDZePWM" wide //weight: 1
        $x_1_7 = "QvrTOZmAkNNXomw" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Crysan_BQT_2147816016_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Crysan.BQT!MTB"
        threat_id = "2147816016"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Crysan"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "17"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "91.243.44.75" ascii //weight: 10
        $x_10_2 = "74.201.28.62" ascii //weight: 10
        $x_10_3 = "taskmgrdev.com/c/" ascii //weight: 10
        $x_10_4 = "reoildriend.sytes.net/cfjhupatesfhgfv/" ascii //weight: 10
        $x_1_5 = "powershell" wide //weight: 1
        $x_1_6 = "-enc aQBwAGMAbwBuAGYAaQBnACAALwByAGUAbgBlAHcA" wide //weight: 1
        $x_1_7 = "-enc UwB0AGEAcgB0AC0AUwBsAGUAZQBwACAALQBTAGUAYwBvAG4AZABzACAAMQAuADUA" wide //weight: 1
        $x_1_8 = "GetMethods" ascii //weight: 1
        $x_1_9 = "GetExportedTypes" ascii //weight: 1
        $x_1_10 = "Invoke" ascii //weight: 1
        $x_1_11 = "DownloadData" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_10_*) and 7 of ($x_1_*))) or
            ((2 of ($x_10_*))) or
            (all of ($x*))
        )
}

rule Trojan_MSIL_Crysan_TENA_2147817272_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Crysan.TENA!MTB"
        threat_id = "2147817272"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Crysan"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {0c 03 07 94 04 6f ?? ?? ?? 0a 20 80 00 00 00 61 5b 0d 09 08 20 00 01 00 00 5a 16 60 59 d2 13 04 06 11 04 6f ?? ?? ?? 0a 00 00 07 17 58 0b 07 03 8e 69 fe 04 13 05 11 05 2d bf}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Crysan_SZK_2147818771_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Crysan.SZK!MTB"
        threat_id = "2147818771"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Crysan"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {7e 06 00 00 04 06 7e 06 00 00 04 06 91 20 ?? ?? ?? 00 59 d2 9c 00 06 17 58 0a 06 7e 06 00 00 04 8e 69 fe 04 0b 07 2d d7}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Crysan_AL_2147823786_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Crysan.AL!MTB"
        threat_id = "2147823786"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Crysan"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {28 1a 00 00 0a 72 57 ?? ?? 70 28 1b ?? ?? 0a 28 05 ?? ?? 06 28 1c ?? ?? 0a 73 1d ?? ?? 0a 25 17 6f 1e ?? ?? 0a 25 17 6f 1f ?? ?? 0a 25 28 1a ?? ?? 0a 72 57 ?? ?? 70 28 1b ?? ?? 0a 6f 20 ?? ?? 0a 28 21 ?? ?? 0a 6f 22 ?? ?? 0a 28 1a ?? ?? 0a 72 57 ?? ?? 70 28 1b ?? ?? 0a 28 23 ?? ?? 0a 1f 0a 28 24 ?? ?? 0a 28 1a ?? ?? 0a 72 6b ?? ?? 70 28 1b ?? ?? 0a 28 06 ?? ?? 06 28 1c ?? ?? 0a 73 1d ?? ?? 0a 25 17}  //weight: 2, accuracy: Low
        $x_1_2 = "WriteAllText" ascii //weight: 1
        $x_1_3 = "get_Assembly" ascii //weight: 1
        $x_1_4 = "get_CurrentDirectory" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Crysan_AN_2147823971_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Crysan.AN!MTB"
        threat_id = "2147823971"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Crysan"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_6_1 = {25 16 1f 23 9d 6f 6f ?? ?? 0a 25 16 9a 6f 2b ?? ?? 0a 0a 25 17 9a 6f 2b ?? ?? 0a 0b 18 9a 6f 2b ?? ?? 0a 0c 3f 00 72 cb ?? ?? 70 6f 6e ?? ?? 0a 17 8d 53 ?? 00 01}  //weight: 6, accuracy: Low
        $x_1_2 = "DownloadData" ascii //weight: 1
        $x_1_3 = "DownloadString" ascii //weight: 1
        $x_1_4 = "WebClient" ascii //weight: 1
        $x_1_5 = "get_Assembly" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Crysan_AS_2147823972_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Crysan.AS!MTB"
        threat_id = "2147823972"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Crysan"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "13"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {16 02 8e 69 28 d5 ?? ?? 06 0c 00 11 04 02}  //weight: 1, accuracy: Low
        $x_1_2 = {fe 09 00 00 fe 09 ?? 00 7e c9 ?? ?? 04 28 33 ?? ?? 06 20 01 ?? ?? 00 28 c0 ?? ?? 06 3a a6 ?? ?? ff 26 38 9c ?? ?? ff 38 1f ?? ?? 00 20 02 ?? ?? 00 38 91 ?? ?? ff 20 00 ?? ?? 00 28 86 ?? 00 06}  //weight: 1, accuracy: Low
        $x_1_3 = "AesCryptoServiceProvider" ascii //weight: 1
        $x_1_4 = "ReadBytes" ascii //weight: 1
        $x_1_5 = "Delegate" ascii //weight: 1
        $x_1_6 = "Trim" ascii //weight: 1
        $x_1_7 = "FromBase64String" ascii //weight: 1
        $x_1_8 = "Encoding" ascii //weight: 1
        $x_1_9 = "CreateDecryptor" ascii //weight: 1
        $x_1_10 = "FlushFinalBlock" ascii //weight: 1
        $x_1_11 = "ToBase64String" ascii //weight: 1
        $x_1_12 = "get_ExecutablePath" ascii //weight: 1
        $x_1_13 = "ReadAllText" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Crysan_ABE_2147824758_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Crysan.ABE!MTB"
        threat_id = "2147824758"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Crysan"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {2b 00 07 2a 22 00 00 20 1d ?? ?? 00 8d 09 ?? ?? 01 25 d0 06 ?? ?? 04 28 0a ?? ?? 0a 0a 06 28 03 ?? ?? 06 0b}  //weight: 1, accuracy: Low
        $x_1_2 = {06 16 73 05 ?? ?? 0a 73 06 ?? ?? 0a 0c 00 08 07 2b 03 00 2b 07 6f 07 ?? ?? 0a 2b f6}  //weight: 1, accuracy: Low
        $x_1_3 = "FromBase64String" ascii //weight: 1
        $x_1_4 = "ToArray" ascii //weight: 1
        $x_1_5 = "WriteByte" ascii //weight: 1
        $x_1_6 = "ReadByte" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Crysan_YFX_2147831001_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Crysan.YFX!MTB"
        threat_id = "2147831001"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Crysan"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {08 11 04 02 11 04 91 06 61 07 09 91 61 d2 9c 07 28}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Crysan_RC_2147834383_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Crysan.RC!MTB"
        threat_id = "2147834383"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Crysan"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {fe 02 16 fe 01 13 21 11 21 2c 06 06 17 58 0a 2b 02 16 0a 17 0b 07 16 fe 01 13 22 11 22 2c 04 16 0b 2b 0f 16 25 0b 13 23 11 23 2c 04}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Crysan_ABEY_2147836680_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Crysan.ABEY!MTB"
        threat_id = "2147836680"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Crysan"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {0a 08 09 6f ?? ?? ?? 0a 7e ?? ?? ?? 04 73 ?? ?? ?? 0a 13 06 11 06 02 7e ?? ?? ?? 04 02 8e 69 6f ?? ?? ?? 0a 11 06 6f ?? ?? ?? 0a dd ?? ?? ?? 00 11 06 39 ?? ?? ?? 00 11 06 6f ?? ?? ?? 0a dc 49 00 09 7e ?? ?? ?? 04 6f}  //weight: 2, accuracy: Low
        $x_1_2 = "CreateDecryptor" ascii //weight: 1
        $x_1_3 = "IsDebuggerPresent" wide //weight: 1
        $x_1_4 = "CAD1094388875" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Crysan_BAN_2147839249_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Crysan.BAN!MTB"
        threat_id = "2147839249"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Crysan"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {06 09 1a 5a 28 ?? 00 00 0a 6e 7e ?? 00 00 04 8e 69 6a 5e 13 04 07 7e ?? 00 00 04 11 04 28 ?? 00 00 0a 28 ?? 00 00 0a 93 6f ?? 00 00 0a 26 09 17 58 0d 09 02 32 ca}  //weight: 2, accuracy: Low
        $x_1_2 = "Welcome To KreYzeTemp Spoofer" wide //weight: 1
        $x_1_3 = "bruh what the fuck" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Crysan_PSGV_2147841107_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Crysan.PSGV!MTB"
        threat_id = "2147841107"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Crysan"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_5_1 = {6f 32 00 00 0a 00 28 be 00 00 06 72 0c 0a 00 70 72 10 0a 00 70 6f 4e 01 00 0a 17 8d ba 00 00 01 25 16 1f 2d 9d 6f 0e 01 00 0a 13 06 11 06 8e 69 8d cd 00 00 01 13 07 16 13 0a 2b 18 11 07 11 0a 11 06 11 0a 9a 1f 10 28 4f 01 00 0a d2 9c 11 0a 17 58 13 0a 11 0a 11 06 8e 69 fe 04 13 0b 11 0b 2d da}  //weight: 5, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Crysan_DAV_2147841693_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Crysan.DAV!MTB"
        threat_id = "2147841693"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Crysan"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_4_1 = {11 05 11 04 06 11 04 8e 69 5d 91 09 06 91 61 d2 6f ?? 00 00 0a 06 0c 08 17 58 0a 06 09 8e 69 32 df}  //weight: 4, accuracy: Low
        $x_1_2 = "GetBytes" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Crysan_AC_2147843058_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Crysan.AC!MTB"
        threat_id = "2147843058"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Crysan"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {02 8e 69 8d 31 00 00 01 0a 02 8e 69 17 59 0b 16 0c 2b 0e 06 08 02 07 91 9c 07 17 59 0b 08 17 58 0c 08 06 8e 69 32 ec}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Crysan_AC_2147843058_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Crysan.AC!MTB"
        threat_id = "2147843058"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Crysan"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {a2 25 17 7e ?? 00 00 0a a2 25 18 09 a2 25 19 17 8c ?? 00 00 01 a2 13 04 14 13 05 07 28 ?? 00 00 0a 72 ?? 02 00 70 6f ?? 00 00 0a 72}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Crysan_AAC_2147843167_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Crysan.AAC!MTB"
        threat_id = "2147843167"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Crysan"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {73 1a 00 00 0a 0a 73 1b 00 00 0a 0b 06 16 73 1c 00 00 0a 73 1d 00 00 0a 0c 08 07 6f 1e 00 00 0a 07 6f 1f 00 00 0a 28 01 00 00 2b 28 02 00 00 2b}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Crysan_ACN_2147843996_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Crysan.ACN!MTB"
        threat_id = "2147843996"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Crysan"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {73 0b 00 00 0a 0a 02 73 0c 00 00 0a 0b 00 06 07 6f ?? ?? ?? 0a 74 01 00 00 1b 0c de 10 07 14 fe 01 0d 09 2d 07 07}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Crysan_ASAN_2147844094_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Crysan.ASAN!MTB"
        threat_id = "2147844094"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Crysan"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {0b 02 16 07 16 07 8e 69 28 ?? ?? ?? 0a 00 06 03 6f ?? ?? ?? 0a 00 06 07 6f ?? ?? ?? 0a 00 73 0f 00 00 0a 0c 00 08 06 6f ?? ?? ?? 0a 17 73 11 00 00 0a 13 04 00 11 04 02 07 8e 69 02 8e 69 07 8e 69 59}  //weight: 2, accuracy: Low
        $x_1_2 = "yedHashAlgorithm" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Crysan_EAS_2147844442_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Crysan.EAS!MTB"
        threat_id = "2147844442"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Crysan"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_3_1 = {02 11 01 28 ?? 00 00 06 13 02 20 00 00 00 00 7e ?? 01 00 04 7b ?? 01 00 04 39 ?? ff ff ff 26 20 00 00 00 00 38 ?? ff ff ff 28 ?? 00 00 0a 11 03 6f ?? 00 00 0a 28 ?? 00 00 0a 13 01 38}  //weight: 3, accuracy: Low
        $x_2_2 = "WindowsFormsApp47.Properties.Resources" wide //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Crysan_EAP_2147844493_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Crysan.EAP!MTB"
        threat_id = "2147844493"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Crysan"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_3_1 = {0a 11 00 28 ?? 00 00 06 28 ?? 00 00 0a 13 03 38 00 00 00 00 73 ?? 00 00 06 25 11 03 28 ?? 00 00 06 6f ?? 00 00 06 13 02 38 00 00 00 00 dd ?? 00 00 00 26 38 00 00 00 00 dd}  //weight: 3, accuracy: Low
        $x_2_2 = "Bawhhwstupwfkbhwpvkmw" wide //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Crysan_EAQ_2147844559_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Crysan.EAQ!MTB"
        threat_id = "2147844559"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Crysan"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_3_1 = {11 04 11 00 18 5b 11 02 11 00 18 6f ?? 00 00 0a 1f 10 28 ?? 00 00 0a 9c 38 ?? 00 00 00 11 03 18 5b 8d ?? 00 00 01 13 04 20 01 00 00 00 7e ?? 00 00 04 7b ?? 00 00 04 3a ?? ff ff ff 26 20 01 00 00 00 38 ?? ff ff ff 11 04 13 06 38 ?? 00 00 00 11 00 18 58 13 00 38}  //weight: 3, accuracy: Low
        $x_2_2 = "WindowsFormsApp84.Properties.Resources" wide //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Crysan_ABRE_2147845865_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Crysan.ABRE!MTB"
        threat_id = "2147845865"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Crysan"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_3_1 = {06 13 01 38 ?? ?? ?? 00 dd ?? ?? ?? ff 26 2f 00 28 ?? ?? ?? 06 13 00 38 ?? ?? ?? 00 28 ?? ?? ?? 06 11 00 6f ?? ?? ?? 0a 28 ?? ?? ?? 0a 28}  //weight: 3, accuracy: Low
        $x_1_2 = "FromBase64String" ascii //weight: 1
        $x_1_3 = "WindowsFormsApp14.Properties.Resources" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Crysan_ABRH_2147845886_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Crysan.ABRH!MTB"
        threat_id = "2147845886"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Crysan"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {28 0e 00 00 06 0a 28 ?? 00 00 0a 06 6f ?? 00 00 0a 28 ?? 00 00 0a 0b 07 16 07 8e 69 28 ?? 00 00 0a 07 0c dd ?? 00 00 00 26 de d4}  //weight: 5, accuracy: Low
        $x_1_2 = "FromBase64String" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Crysan_AACN_2147849625_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Crysan.AACN!MTB"
        threat_id = "2147849625"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Crysan"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_3_1 = {28 09 00 00 0a 03 50 6f ?? 00 00 0a 6f ?? 00 00 0a 0b 73 ?? 00 00 0a 0c 08 07 6f ?? 00 00 0a 08 18 6f ?? 00 00 0a 08 6f ?? 00 00 0a 02 50 16 02 50 8e 69 6f ?? 00 00 0a 2a}  //weight: 3, accuracy: Low
        $x_1_2 = "CreateDecryptor" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Crysan_AAET_2147850710_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Crysan.AAET!MTB"
        threat_id = "2147850710"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Crysan"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {0b 06 07 16 1a 6f ?? 00 00 0a 26 07 16 28 ?? 00 00 0a 0c 06 16 73 ?? 00 00 0a 0d 08 8d ?? 00 00 01 13 04 09 11 04 16 08 6f ?? 00 00 0a 26 11 04 28 ?? 00 00 2b 28 ?? 00 00 2b 13 05 de 14 09 2c 06 09 6f ?? 00 00 0a dc}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Crysan_AAFB_2147850718_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Crysan.AAFB!MTB"
        threat_id = "2147850718"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Crysan"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {0c 08 8e 69 8d ?? 00 00 01 0d 16 13 05 2b 18 09 11 05 08 11 05 91 07 11 05 07 8e 69 5d 91 61 d2 9c 11 05 17 58 13 05 11 05 08 8e 69 32 e1}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Crysan_ABS_2147850825_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Crysan.ABS!MTB"
        threat_id = "2147850825"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Crysan"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {00 0f 00 08 20 00 04 00 00 58 28 01 00 00 2b 00 07 02 08 20 00 04 00 00 6f ?? 00 00 0a 0d 08 09 58 0c 00 09 20 00 04 00 00 fe 04 16 fe 01 13 04 11 04 2d cc}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Crysan_AAFZ_2147851069_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Crysan.AAFZ!MTB"
        threat_id = "2147851069"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Crysan"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {0a 0b 06 16 fe 0e 03 00 20 fc ff ff ff 20 ba 8e fa fb 20 54 0e d4 88 61 20 ee 80 2e 73 40 ?? 00 00 00 20 02 00 00 00 fe 0e 03 00 fe ?? ?? 00 00 01 58 00 73 ?? 00 00 0a 0c 08 07 6f ?? 00 00 0a 08 6f ?? 00 00 0a 07 6f ?? 00 00 0a 06 6f ?? 00 00 0a 07 6f ?? 00 00 0a 2a}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Crysan_AAHK_2147851701_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Crysan.AAHK!MTB"
        threat_id = "2147851701"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Crysan"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {0b 06 16 fe 0e 03 00 20 fc ff ff ff 20 2d 2c b7 a2 20 61 af f7 77 61 20 4c 83 40 d5 40 ?? 00 00 00 20 02 00 00 00 fe 0e 03 00 fe ?? ?? 00 00 01 58 00 73 ?? 00 00 0a 0c 08 07 6f ?? 00 00 0a 08 6f ?? 00 00 0a 07 6f ?? 00 00 0a 06 6f ?? 00 00 0a 07 6f ?? 00 00 0a 2a}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Crysan_AAHW_2147851860_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Crysan.AAHW!MTB"
        threat_id = "2147851860"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Crysan"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_4_1 = {0a 0c 08 28 ?? 00 00 0a 04 6f ?? 00 00 0a 6f ?? 00 00 0a 0d 07 09 6f ?? 00 00 0a 00 07 18 6f ?? 00 00 0a 00 07 6f ?? 00 00 0a 03 16 03 8e 69 6f ?? 00 00 0a 0a 2b 00 06 2a}  //weight: 4, accuracy: Low
        $x_1_2 = "CreateDecryptor" ascii //weight: 1
        $x_1_3 = "TransformFinalBlock" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Crysan_NYS_2147852200_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Crysan.NYS!MTB"
        threat_id = "2147852200"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Crysan"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {02 28 28 00 00 0a 0a 73 ?? 00 00 0a 0b 07 28 ?? 00 00 0a 03 6f ?? 00 00 0a 6f ?? 00 00 0a 0c 73 ?? 00 00 0a 13 06 11 06 08 6f ?? 00 00 0a 11 06 18 6f ?? 00 00 0a 11 06 18 6f ?? 00 00 0a 11 06 0d 09 6f ?? 00 00 0a 13 04 11 04 06 16 06 8e 69 6f ?? 00 00 0a 13 05 28 ?? 00 00 0a 11 05 6f ?? 00 00 0a 13 07 de 14}  //weight: 5, accuracy: Low
        $x_1_2 = "cdrkSI.resources" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Crysan_AAIO_2147852219_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Crysan.AAIO!MTB"
        threat_id = "2147852219"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Crysan"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_4_1 = {11 04 09 6f ?? 00 00 0a 11 04 07 6f ?? 00 00 0a 11 04 11 04 6f ?? 00 00 0a 11 04 6f ?? 00 00 0a 6f ?? 00 00 0a 13 05 02 28 ?? 00 00 0a 73 ?? 00 00 0a 13 06 11 06 11 05 16 73 ?? 00 00 0a 13 07 11 07 73 ?? 00 00 0a 13 08 11 08 6f ?? 00 00 0a 0a dd ?? 00 00 00 11 08 39 ?? 00 00 00 11 08 6f ?? 00 00 0a dc}  //weight: 4, accuracy: Low
        $x_1_2 = "CreateDecryptor" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Crysan_AAJE_2147852546_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Crysan.AAJE!MTB"
        threat_id = "2147852546"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Crysan"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_4_1 = {0a 0c 07 16 28 ?? 00 00 0a 0d 08 07 1a 07 8e 69 1a da 6f ?? 00 00 0a 00 09 17 da 17 d6 8d ?? 00 00 01 13 04 08 16 6a 6f ?? 00 00 0a 00 00 08 16 73 ?? 00 00 0a 13 05 11 05 11 04 16 11 04 8e 69 6f ?? 00 00 0a 26 de 0e 00 11 05 2c 08 11 05 6f ?? 00 00 0a 00 dc 28 ?? 00 00 0a 11 04 16 11 04 8e 69 6f ?? 00 00 0a 0a de 0c}  //weight: 4, accuracy: Low
        $x_1_2 = "tniopyrtnE" wide //weight: 1
        $x_1_3 = "ekovnI" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Crysan_AAKU_2147853214_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Crysan.AAKU!MTB"
        threat_id = "2147853214"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Crysan"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_4_1 = {11 08 11 09 16 11 09 8e 69 28 ?? 00 00 06 20 01 00 00 00 7e ?? 00 00 04 7b ?? 00 00 04 3a ?? ff ff ff 26 20 01 00 00 00 38 ?? ff ff ff 11 02 28 ?? 00 00 06 13 07 20 02 00 00 00 38}  //weight: 4, accuracy: Low
        $x_1_2 = "FromBase64String" ascii //weight: 1
        $x_1_3 = "CreateDecryptor" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Crysan_AALA_2147887406_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Crysan.AALA!MTB"
        threat_id = "2147887406"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Crysan"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {0d 06 13 04 11 04 8e 69 8d ?? 00 00 01 13 05 16 13 06 38 ?? 00 00 00 11 05 11 06 11 04 11 06 91 09 28 ?? 00 00 0a 59 d2 9c 11 06 17 58 13 06 11 06 11 04 8e 69 32 e0}  //weight: 5, accuracy: Low
        $x_1_2 = "ReadAsByteArrayAsync" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Crysan_AALH_2147888152_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Crysan.AALH!MTB"
        threat_id = "2147888152"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Crysan"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_4_1 = {72 ef 00 00 70 6f ?? 00 00 0a 0a 73 ?? 00 00 0a 0b 73 ?? 00 00 0a 0c 08 06 6f ?? 00 00 0a 0d 07 09 6f ?? 00 00 0a 07 18 6f ?? 00 00 0a 02 13 04 07 6f ?? 00 00 0a 11 04 16 11 04 8e 69 6f ?? 00 00 0a 13 05}  //weight: 4, accuracy: Low
        $x_1_2 = "CreateDecryptor" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Crysan_AMAA_2147889485_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Crysan.AMAA!MTB"
        threat_id = "2147889485"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Crysan"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {0a 0b 06 72 ?? 00 00 70 28 ?? 00 00 0a 07 72 ?? 00 00 70 6f ?? 00 00 0a 74 ?? 00 00 1b 28 ?? 00 00 0a 06 72 ?? 00 00 70 28 ?? 00 00 0a 28 ?? 00 00 0a 26 06 72 ?? 00 00 70 28 ?? 00 00 0a 07 72 ?? 00 00 70 6f ?? 00 00 0a 74 ?? 00 00 1b 28 ?? 00 00 0a 06 72 ?? 00 00 70 28 ?? 00 00 0a 28 ?? 00 00 0a 26 de 14}  //weight: 1, accuracy: Low
        $x_1_2 = "WriteAllBytes" ascii //weight: 1
        $x_1_3 = "GetObject" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Crysan_AMAB_2147889488_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Crysan.AMAB!MTB"
        threat_id = "2147889488"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Crysan"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {0a 08 11 04 6f ?? 00 00 0a 08 08 6f ?? 00 00 0a 08 ?? 21 00 00 0a 6f ?? 00 00 0a 13 05 73 ?? 00 00 0a 13 06 11 06 11 05 17 73 ?? 00 00 0a 13 07 06 72 ?? ?? ?? 70 6f ?? 00 00 0a 2c 5d 06 06 72 ?? ?? ?? 70 6f ?? 00 00 0a 72 ?? ?? ?? 70 28 ?? 00 00 0a 58 6f ?? 00 00 0a 28 ?? 00 00 0a 13 08 11 07 11 08 16 11 08 8e 69 6f ?? 00 00 0a 11 07 6f ?? 00 00 0a 11 07 6f ?? 00 00 0a 11 06 6f ?? 00 00 0a 28 ?? 00 00 0a 6f ?? 00 00 0a 14 16 8d}  //weight: 1, accuracy: Low
        $x_1_2 = "CreateDecryptor" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Crysan_AAOL_2147890077_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Crysan.AAOL!MTB"
        threat_id = "2147890077"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Crysan"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {16 13 09 2b 22 11 07 11 09 58 06 11 09 58 47 08 11 09 08 6f ?? 00 00 0a 5d 6f ?? 00 00 0a 61 d2 52 11 09 17 58 13 09 11 09 07 8e 69 32 d7}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Crysan_AAON_2147890079_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Crysan.AAON!MTB"
        threat_id = "2147890079"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Crysan"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_5_1 = {16 0c 2b 13 00 07 08 07 08 91 20 81 02 00 00 59 d2 9c 00 08 17 58 0c 08 07 8e 69 fe 04 0d 09 2d e3}  //weight: 5, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Crysan_AAQP_2147891990_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Crysan.AAQP!MTB"
        threat_id = "2147891990"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Crysan"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_4_1 = {0a 06 18 6f ?? 02 00 0a 06 1b 6f ?? 02 00 0a 06 6f ?? 02 00 0a 0d 09 04 16 04 8e 69 6f ?? 01 00 0a 13 04 de 21}  //weight: 4, accuracy: Low
        $x_1_2 = "CreateDecryptor" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Crysan_ACR_2147892018_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Crysan.ACR!MTB"
        threat_id = "2147892018"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Crysan"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {0a de 03 26 de 00 72 ?? 00 00 70 0a 72 ?? 00 00 70 06 28 ?? 00 00 0a 26 2a}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Crysan_ACR_2147892018_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Crysan.ACR!MTB"
        threat_id = "2147892018"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Crysan"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {16 2d 16 00 06 16 6f ?? 00 00 0a 0c 16 0d 2b 1a 16 2d b5 08 09 91 13 04 00 07 11 04 6f ?? 00 00 0a 00 00 09 19 2c 04 17 58}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Crysan_ACR_2147892018_2
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Crysan.ACR!MTB"
        threat_id = "2147892018"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Crysan"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {0c 08 06 73 12 00 00 0a 07 6f ?? 00 00 0a 00 73 14 00 00 0a 0d 09 20 e8 03 00 00 20 b8 0b 00 00 6f ?? 00 00 0a 13 04 11 04 28}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Crysan_ACR_2147892018_3
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Crysan.ACR!MTB"
        threat_id = "2147892018"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Crysan"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {28 01 00 00 06 0a 06 16 28 02 00 00 06 26 28 04 00 00 06 6f 05 00 00 0a 2a}  //weight: 1, accuracy: High
        $x_1_2 = {7d 04 00 00 04 12 00 7b 05 00 00 04 0b 12 01 12 00 28 02 00 00 2b 12 00 7c 05 00 00 04 28 28 00 00 0a 2a}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Crysan_ACR_2147892018_4
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Crysan.ACR!MTB"
        threat_id = "2147892018"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Crysan"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {13 06 2b 73 11 06 6f ?? 00 00 0a 74 ?? 00 00 01 13 07 00 1b 28 ?? 00 00 0a 00 07 11 07 6f ?? 00 00 0a 6f ?? 00 00 0a 13 08 11 08 2c 49 00 1f 0e 28 ?? 00 00 0a 00 72 ?? 04 00 70 11 04 6f}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Crysan_AARH_2147892390_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Crysan.AARH!MTB"
        threat_id = "2147892390"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Crysan"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_3_1 = {06 0a 04 73 ?? 00 00 06 0b 07 6f ?? 00 00 06 00 06 0c 2b 00 08 2a}  //weight: 3, accuracy: Low
        $x_1_2 = "CreateDecryptor" wide //weight: 1
        $x_1_3 = "b95Rp622Qxep43HnEbMqAg==" wide //weight: 1
        $x_1_4 = "t1+CVi4GffYRslmj3aNijQ==" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Crysan_SM_2147892531_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Crysan.SM!MTB"
        threat_id = "2147892531"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Crysan"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {07 08 07 08 91 20 81 02 00 00 59 d2 9c 00 08 17 58 0c 08 07 8e 69 fe 04 0d 09 2d e3}  //weight: 2, accuracy: High
        $x_2_2 = "SistemaAsistencias.Logica" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Crysan_SPQI_2147895482_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Crysan.SPQI!MTB"
        threat_id = "2147895482"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Crysan"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_4_1 = {38 22 00 00 00 00 28 ?? ?? ?? 06 16 fe 01 0d 09 39 06 00 00 00 28 ?? ?? ?? 06 00 20 ?? ?? ?? 00 28 ?? ?? ?? 0a 00 00 17 13 04 38 d6 ff ff ff}  //weight: 4, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Crysan_GILCH_2147896115_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Crysan.GILCH!MTB"
        threat_id = "2147896115"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Crysan"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_10_1 = {20 42 cd 48 07 61 25 13 0c 1f 17 5e 45 17 00 00 00 15 01 00 00 a1 01 00 00 60 01 00 00 01 02}  //weight: 10, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Crysan_KTS_2147896116_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Crysan.KTS!MTB"
        threat_id = "2147896116"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Crysan"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {11 04 11 09 7e 03 00 00 04 11 09 7e 03 00 00 04 8e 69 5d 91 9e 11 09 17 58 13 09 11 09 72 cd 00 00 70 28 ?? ?? ?? 0a 32 d7}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Crysan_LRA_2147896145_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Crysan.LRA!MTB"
        threat_id = "2147896145"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Crysan"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "18"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "smm2021.net" ascii //weight: 10
        $x_10_2 = "178.250.159.150" ascii //weight: 10
        $x_1_3 = "powershell" wide //weight: 1
        $x_1_4 = "-enc UwB0AGEAcgB0AC0AUwBsAGUAZQBwACAALQBTAGUAYwBv" wide //weight: 1
        $x_1_5 = "GetMethod" ascii //weight: 1
        $x_1_6 = "DownloadData" ascii //weight: 1
        $x_1_7 = "Invoke" ascii //weight: 1
        $x_1_8 = "WebClient" ascii //weight: 1
        $x_1_9 = "GetExportedTypes" ascii //weight: 1
        $x_1_10 = "ToArray" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_10_*) and 8 of ($x_1_*))) or
            ((2 of ($x_10_*))) or
            (all of ($x*))
        )
}

rule Trojan_MSIL_Crysan_SO_2147897288_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Crysan.SO!MTB"
        threat_id = "2147897288"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Crysan"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {8d 0d 00 00 01 25 16 07 1e 63 d2 1f 1f 61 d2 9c 25 17 07 1f 10 63 d2 1f 11 61 d2 9c 25 18 07 1f 38 63 d2 20 e4 00 00 00 61 d2 9c 25 19 07 16 63 d2 20 ed 00 00 00 61 d2 9c 25 1a 07 1f 18 63 d2 20 d2 00 00 00 61 d2 9c 25 1b 07 1f 30 63 d2 20 f9 00 00 00 61 d2 9c 25 1c 07 1f 28 63 d2 20 f1 00 00 00 61 d2 9c 25 1d 07 1f 20 63 d2 1f 21 61 d2 9c 28 0f 00 00 0a 38 97 00 00 00}  //weight: 2, accuracy: High
        $x_2_2 = "676DAE618EEF96057FA773673F8E25B4ECFD68FC" ascii //weight: 2
        $x_2_3 = "Stub.Rummage.exe" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Crysan_SN_2147897497_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Crysan.SN!MTB"
        threat_id = "2147897497"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Crysan"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {02 09 28 e2 00 00 0a 03 09 03 6f 40 00 00 0a 5d 17 d6 28 e2 00 00 0a da 13 04 07 11 04 28 e3 00 00 0a 28 e4 00 00 0a 28 41 00 00 0a 0b 09 17 d6 0d 09 08 31 cb}  //weight: 2, accuracy: High
        $x_2_2 = "$f193611f-4452-42c0-abc9-9b14fe9bc63f" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Crysan_SSXP_2147899946_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Crysan.SSXP!MTB"
        threat_id = "2147899946"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Crysan"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_4_1 = {0a 73 10 00 00 0a 0b 00 00 20 00 0c 00 00 28 ?? ?? ?? 0a 00 07 06 72 6e 01 00 70 6f ?? ?? ?? 0a 00 72 6e 01 00 70 28 ?? ?? ?? 0a 26 00 de 05}  //weight: 4, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Crysan_SXXP_2147900223_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Crysan.SXXP!MTB"
        threat_id = "2147900223"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Crysan"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_4_1 = {11 08 11 09 11 07 11 0a 25 17 58 13 0a 91 08 61 d2 9c 09 17 5f 17 33 07 11 0a 11 04 58 13 0a 08 1b 64 08 1f 1b 62 60 1d 5a 0c 09 17 64 09 1f 1f 62 60 0d 11 09 17 58 13 09 11 09 6a 20 00 16 0d 01 6a 32 bc}  //weight: 4, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Crysan_MVH_2147901632_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Crysan.MVH!MTB"
        threat_id = "2147901632"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Crysan"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "StartKeyloaggar" ascii //weight: 2
        $x_1_2 = "hookID" ascii //weight: 1
        $x_1_3 = "DecryptBytes" ascii //weight: 1
        $x_1_4 = "ActivatePong" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 2 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Trojan_MSIL_Crysan_GPA_2147902138_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Crysan.GPA!MTB"
        threat_id = "2147902138"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Crysan"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_5_1 = {56 00 46 00 5a 00 78 00 55 00 55 00 46 00 42 00 54 00 55 00 46 00 42 00 87 65 55 00 46 00 46 00 87 65 55 00 46 00 42 00 87 65 53 00 38 00 76 00 4f 00 45 00 46 00 42 00 54 00 47 00 64 00 42 00 87 65 55 00 46 00 42 00 87 65 55 00 46 00 42 00 87 65 55 00 46 00 52 00 87 65 55 00 46 00 42 00 87 65}  //weight: 5, accuracy: High
        $x_5_2 = {00 52 65 70 6c 61 63 65 00}  //weight: 5, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Crysan_SP_2147903202_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Crysan.SP!MTB"
        threat_id = "2147903202"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Crysan"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {28 07 00 00 06 0b 07 8e 69 20 00 04 00 00 2e f0}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Crysan_ACY_2147904344_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Crysan.ACY!MTB"
        threat_id = "2147904344"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Crysan"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {06 8e 69 17 58 20 00 30 00 00 1f 40 28 ?? 00 00 06 13 05 11 05 7e ?? 00 00 0a 28 ?? 00 00 0a 13 0c 11 0c 2c 05 ?? ?? ?? ?? ?? 11 04 11 05 06 06 8e 69 12 0e 28}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Crysan_ACY_2147904344_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Crysan.ACY!MTB"
        threat_id = "2147904344"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Crysan"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {18 11 23 58 19 5d 13 26 19 8d ?? 00 00 01 13 27 11 27 16 12 20 28 ?? 00 00 0a 9c 11 27 17 12 20 28 ?? 00 00 0a 9c 11 27 18 12 20 28 ?? 00 00 0a 9c 11 22 16 fe 02}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Crysan_ACY_2147904344_2
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Crysan.ACY!MTB"
        threat_id = "2147904344"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Crysan"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {0a 00 2b 0a 00 1f 64 28 ?? 00 00 0a 00 00 09 6f ?? 00 00 0a 13 07 11 07 2d ea 11 05 73 ?? 00 00 0a 13 06 11 06 17 6f}  //weight: 1, accuracy: Low
        $x_1_2 = {0a 00 11 06 28 ?? 00 00 0a 26 00 de 1d 13 08 00 72 ?? 00 00 70 11 08 6f ?? 00 00 0a 28 ?? 00 00 0a 28}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Crysan_RDB_2147917407_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Crysan.RDB!MTB"
        threat_id = "2147917407"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Crysan"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {07 08 18 6f 19 00 00 0a 1f 10 28 1a 00 00 0a 6f 1b 00 00 0a 08 18 58 0c}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Crysan_ARA_2147920531_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Crysan.ARA!MTB"
        threat_id = "2147920531"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Crysan"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {08 1f 20 3c ?? ?? ?? 00 07 08 18 5b 03 08 18 6f ?? ?? ?? 0a 1f 10 28 ?? ?? ?? 0a 9c 38 ?? ?? ?? 00 08 18 5b 1f 10 59 0d 06 09 03 08 18 6f ?? ?? ?? 0a 1f 10 28 ?? ?? ?? 0a 07 09 07 8e 69 5d 91 61 d2 9c 08 18 58 0c 08 03 6f ?? ?? ?? 0a 3f}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Crysan_MX_2147925520_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Crysan.MX!MTB"
        threat_id = "2147925520"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Crysan"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {11 0b 11 08 6f ?? 00 00 0a 26}  //weight: 2, accuracy: Low
        $x_2_2 = {09 7e 0d 00 00 04 28 16 00 00 06 13 05}  //weight: 2, accuracy: High
        $x_3_3 = "polatfamilyengine" ascii //weight: 3
        $x_1_4 = "BlockCopy" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_3_*) and 1 of ($x_2_*) and 1 of ($x_1_*))) or
            ((1 of ($x_3_*) and 2 of ($x_2_*))) or
            (all of ($x*))
        )
}

rule Trojan_MSIL_Crysan_AMCU_2147929115_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Crysan.AMCU!MTB"
        threat_id = "2147929115"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Crysan"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {0a 0c 08 72 ?? 00 00 70 28 ?? 00 00 0a 6f ?? 00 00 0a 08 72 ?? 00 00 70 28 ?? 00 00 0a 6f ?? 00 00 0a 08 6f ?? 00 00 0a 07 16 07 8e 69 6f ?? 00 00 0a 0b dd}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Crysan_PLLZH_2147930989_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Crysan.PLLZH!MTB"
        threat_id = "2147930989"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Crysan"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_6_1 = {fe 0c 00 00 fe 0d 03 00 28 ?? 00 00 0a 6f ?? 00 00 0a fe 0c 00 00 fe 0d 03 00 28 ?? 00 00 0a 6f ?? 00 00 0a fe 0c 00 00 fe 0d 03 00 28 ?? 00 00 0a 6f ?? 00 00 0a fe 0c 02 00}  //weight: 6, accuracy: Low
        $x_4_2 = {fe 09 00 00 fe 0c 01 00 fe 0c 02 00 6f ?? 00 00 0a fe 0e 03 00}  //weight: 4, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Crysan_CCJR_2147931800_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Crysan.CCJR!MTB"
        threat_id = "2147931800"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Crysan"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "tDActIQ7U7SS4ebJS7EaOA==" ascii //weight: 2
        $x_1_2 = "HfgOq4jUIgE=" ascii //weight: 1
        $x_1_3 = "c:\\temp\\Assembly.exe" ascii //weight: 1
        $x_1_4 = "Bcifjhzvuw" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Crysan_ARAZ_2147932156_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Crysan.ARAZ!MTB"
        threat_id = "2147932156"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Crysan"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {11 05 11 06 9a 0c 08 12 03 28 ?? ?? ?? 0a 2c 17 06 09 7e ?? ?? ?? 04 61 d1 13 07 12 07 28 ?? ?? ?? 0a 6f ?? ?? ?? 0a 11 06 17 58 13 06 11 06 11 05 8e 69 32 cb}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Crysan_PHV_2147934982_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Crysan.PHV!MTB"
        threat_id = "2147934982"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Crysan"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {13 06 08 20 b7 5c 8a 00 6a 5e 6d 13 07 16 13 0b 2b 2b 11 05 11 0b 8f ?? 00 00 01 25 47 08 d2 61 d2 52 11 0b 20 ff 00 00 00 5f 2d 0b 08 08 5a 20 b7 5c 8a 00 6a 5e 0c 11 0b 17 58 13 0b 11 0b 11 05 8e 69 32 cd}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Crysan_SKDA_2147936087_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Crysan.SKDA!MTB"
        threat_id = "2147936087"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Crysan"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {63 d1 13 13 11 1e 11 09 91 13 27 11 1e 11 09 11 23 11 27 61 11 1b 19 58 61 11 2a 61 d2 9c}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Crysan_EAXO_2147936728_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Crysan.EAXO!MTB"
        threat_id = "2147936728"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Crysan"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_5_1 = {00 73 56 00 00 0a 0a 16 0b 2b 1d 00 06 72 fb 07 00 70 07 8c 45 00 00 01 28 36 00 00 0a 6f 57 00 00 0a 26 00 07 17 58 0b 07 20 e8 03 00 00 fe 04 0c 08 2d d7}  //weight: 5, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Crysan_EARX_2147938601_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Crysan.EARX!MTB"
        threat_id = "2147938601"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Crysan"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_5_1 = {02 8e 69 8d 0b 00 00 01 0a 16 0b 38 25 00 00 00 02 07 91 0c 08 18 28 06 00 00 06 0c 08 03 59 07 59 20 ff 00 00 00 5f d2 0c 08 66 d2 0c 06 07 08 9c 07 17 58 0b 07 02 8e 69 32 d5 06 2a}  //weight: 5, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Crysan_PGC_2147939519_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Crysan.PGC!MTB"
        threat_id = "2147939519"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Crysan"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_4_1 = "13432D45435o4365w65n46l575o75a4d56S3t5435r4i5n6546g53523423" ascii //weight: 4
        $x_1_2 = "109=7928A96738/564754m64156]45263s5334'5344534i54135S242c324323a4[1[2n3]4B1[2[3u4f1f2]3]4[1e23]43122r3" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Crysan_EAFS_2147939541_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Crysan.EAFS!MTB"
        threat_id = "2147939541"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Crysan"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_5_1 = {08 23 00 00 00 00 00 00 f0 3f 11 04 6c 23 00 00 00 00 00 00 24 40 5b 28 cd 00 00 0a 23 7b 14 ae 47 e1 7a 94 3f 5a 58 5a 0c 11 04 17 d6 13 04 11 04 09 31 cc}  //weight: 5, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Crysan_EAZE_2147939542_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Crysan.EAZE!MTB"
        threat_id = "2147939542"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Crysan"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_5_1 = {00 0f 00 08 20 00 04 00 00 58 28 01 00 00 2b 00 07 02 08 20 00 04 00 00 6f 13 00 00 0a 0d 08 09 58 0c 09 20 00 04 00 00 fe 04 13 04 11 04 2c 0c 00 0f 00 08 28 01 00 00 2b 00 2b 06 00 17 13 05 2b be}  //weight: 5, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Crysan_NC_2147940069_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Crysan.NC!MTB"
        threat_id = "2147940069"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Crysan"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_3_1 = {73 79 04 00 06 0a 06 03 7d bf 00 00 04 02 6f 0c 00 00 0a 06 fe 06 7a 04 00 06 73 0d 00 00 0a 28 04 00 00 2b 25}  //weight: 3, accuracy: High
        $x_1_2 = {28 09 00 00 0a 02 6f 0a 00 00 0a 0a dd 07 00 00 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Crysan_BAA_2147941285_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Crysan.BAA!MTB"
        threat_id = "2147941285"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Crysan"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {03 04 05 06 58 0e 04 06 59 ?? ?? ?? ?? ?? 0b 07 3a 0b 00 00 00 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 7a 06 07 58 0a 06 0e 04 32 d7}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Crysan_BAA_2147941285_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Crysan.BAA!MTB"
        threat_id = "2147941285"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Crysan"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {6f 11 00 00 0a 0c 08 6f 12 00 00 0a 0d 09 02 16 02 8e 69 6f 13 00 00 0a 13 04 dd 1a 00 00 00 09 39 06 00 00 00 09 6f 0b 00 00 0a dc 08 39 06 00 00 00 08 6f 0b 00 00 0a dc}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Crysan_ACA_2147943543_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Crysan.ACA!MTB"
        threat_id = "2147943543"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Crysan"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_3_1 = {0a 16 0b 2b 1e 06 07 02 07 6f ?? 00 00 0a 03 07 03 6f ?? 00 00 0a 5d 6f ?? 00 00 0a 61 d1 9d 07 17 58 0b 07 02 6f ?? 00 00 0a fe 04 0c 08}  //weight: 3, accuracy: Low
        $x_2_2 = {0a 07 17 6f ?? 00 00 0a 0c 00 08 2d 02 2b 18 08 06 72 ?? 00 00 70 02 72 ?? 00 00 70 28 ?? 00 00 0a 28 ?? 00 00 0a 00 00 de 0b 08 2c 07 08 6f}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Crysan_GVA_2147943601_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Crysan.GVA!MTB"
        threat_id = "2147943601"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Crysan"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "://apstori.ru/panel" wide //weight: 2
        $x_1_2 = "RgyNO7Fqn" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Crysan_GVB_2147943602_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Crysan.GVB!MTB"
        threat_id = "2147943602"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Crysan"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {7e 05 00 00 04 25 39 05 00 00 00 38 17 00 00 00 26 7e 04 00 00 04 fe 06 0f 00 00 06 73 07 00 00 0a 25 80 05 00 00 04 28 01 00 00 2b 13 02}  //weight: 1, accuracy: High
        $x_1_2 = {0b 07 20 c0 00 00 00 5f 20 c0 00 00 00 40 2d 00 00 00 07 20 c0 00 00 00 61 1e 62 02 28 c1 02 00 06 60 0c 02 7b 14 01 00 04 08 6f 11 01 00 0a 0d 02 7b 14 01 00 04}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_MSIL_Crysan_BAB_2147943948_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Crysan.BAB!MTB"
        threat_id = "2147943948"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Crysan"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {0a 73 56 00 00 0a 0b 1a 8d 06 00 00 01 0c 06 08 16 1a 6f 35 00 00 0a 1a 2e 06 73 5a 00 00 0a 7a 06 16 73 5b 00 00 0a 0d 09 07 6f 57 00 00 0a de 07 09 6f 59 00 00 0a dc 07 6f 58 00 00 0a 13 04 de 0e 07 6f 59 00 00 0a dc}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Crysan_BAB_2147943948_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Crysan.BAB!MTB"
        threat_id = "2147943948"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Crysan"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {11 02 11 01 6f 17 00 00 0a 38 00 00 00 00 11 02 6f 18 00 00 0a 13 03 38 0e 00 00 00 11 02 11 00 6f 19 00 00 0a 38 d6 ff ff ff 00 02 73 1a 00 00 0a 13 04 38 00 00 00 00 00 11 04 11 03 16 73 1b 00 00 0a 13 05 38 00 00 00 00 00 73 1c 00 00 0a 13 06 38 00 00 00 00 00}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Crysan_EYII_2147943991_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Crysan.EYII!MTB"
        threat_id = "2147943991"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Crysan"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {11 2a 1d 11 0b 5f 91 13 1e 11 1e 19 62 11 1e 1b 63 60 d2 13 1e 11 06 11 0b 11 06 11 0b 91 11 1e 61 d2}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Crysan_EHHL_2147943993_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Crysan.EHHL!MTB"
        threat_id = "2147943993"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Crysan"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {11 07 11 0e 11 10 11 0e 6c 11 10 6c ?? ?? ?? ?? ?? 11 0e 11 10 d6 17 d6 6c 5b ?? ?? ?? ?? ?? 11 10 17 d6 13 10 11 10 11 0f 31 d5}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Crysan_ENTP_2147943995_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Crysan.ENTP!MTB"
        threat_id = "2147943995"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Crysan"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {03 08 03 08 91 08 04 ?? ?? ?? ?? ?? 9c 08 17 d6 0c 08 07 31 eb}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Crysan_AE_2147945010_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Crysan.AE!MTB"
        threat_id = "2147945010"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Crysan"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {20 a6 c5 6b cd 80 9e 00 00 04 17 80 9f 00 00 04 72 d7 0a 00 70 80 a0 00 00 04 17 80 a1 00 00 04 72 05 0b 00 70 80 a2 00 00 04 21}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Crysan_AB_2147945979_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Crysan.AB!MTB"
        threat_id = "2147945979"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Crysan"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {0a 0b 20 00 04 00 00 8d 46 00 00 01 0c 38 09 00 00 00 07 08 16 09 6f 69 00 00 0a 06 08 16 08 8e 69 6f}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Crysan_EPO_2147946270_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Crysan.EPO!MTB"
        threat_id = "2147946270"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Crysan"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {11 2a 11 0b 1d 5f 91 13 1e 11 1e 19 62 11 1e 1b 63 60 d2 13 1e 11 06 11 0b 11 06 11 0b 91 11 1e 61 d2 9c 17 11 0b 58 13 0b 11 0b 11 07 32 d1}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Crysan_ZJQ_2147947740_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Crysan.ZJQ!MTB"
        threat_id = "2147947740"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Crysan"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "11"
        strings_accuracy = "Low"
    strings:
        $x_6_1 = {7a 11 02 16 28 ?? 00 00 0a 13 03 38 ?? ff ff ff 73 ?? 00 00 0a 7a 11 00 16 73 ?? 00 00 0a 13 04 38 ?? ff ff ff 11 01 6f ?? 00 00 0a 25 8e 69 11 03 3b}  //weight: 6, accuracy: Low
        $x_5_2 = {11 01 11 05 16 11 06 6f ?? 00 00 0a 38 ?? 00 00 00 11 04 11 05 16 11 05 8e 69 6f ?? 00 00 0a 25 13 06 16}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Crysan_AYA_2147947749_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Crysan.AYA!MTB"
        threat_id = "2147947749"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Crysan"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {16 13 21 2b 37 00 11 0a 11 21 11 20 6f ?? 00 00 0a 13 22 11 0c 12 22 28 ?? 00 00 0a 1f 10 62 12 22 28 ?? 00 00 0a 1e 62 60 12 22 28 ?? 00 00 0a 60 6a 61 13 0c 00 11 21 19 58 13 21}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Crysan_AYA_2147947749_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Crysan.AYA!MTB"
        threat_id = "2147947749"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Crysan"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_7_1 = {00 02 08 91 08 20 ff 00 00 00 5f 61 06 08 06 8e 69 5d 91 58 0d 07 08 09 20 ff 00 00 00 5f d2 9c 00 08 17 58 0c 08 02 8e 69 fe 04 13 07 11 07 2d cf}  //weight: 7, accuracy: High
        $x_1_2 = "Obfuscated payload stored in registry" wide //weight: 1
        $x_1_3 = "CreateSequentialPersistence" ascii //weight: 1
        $x_1_4 = "IsWindowsDefenderEnabled" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Crysan_AYS_2147947910_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Crysan.AYS!MTB"
        threat_id = "2147947910"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Crysan"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {1e 5a 0a 06 1f 40 fe 01 0b 07 2c 18 00 7e ?? 00 00 0a 7e ?? 00 00 04 28 ?? 00 00 06 80 04 00 00 04 00 2b 1f 06 1f 20 fe 01 0c 08 2c 16}  //weight: 2, accuracy: Low
        $x_1_2 = {02 03 8e 69 20 00 10 00 00 1f 40 28 ?? 00 00 06 0a 06 7e ?? 00 00 0a 28 ?? 00 00 0a 0b 07 2c 0b 28 ?? 00 00 0a 73 ?? 00 00 0a 7a 03 16 06 03 8e 69}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Crysan_AYC_2147947925_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Crysan.AYC!MTB"
        threat_id = "2147947925"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Crysan"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {13 04 16 13 05 2b 1d 09 02 11 05 6f ?? 00 00 0a 06 61 d1 28 ?? 00 00 0a 28 ?? 00 00 0a 0d 11 05 17 58 13 05 11 05 11 04}  //weight: 2, accuracy: Low
        $x_1_2 = {1e 5a 0a 06 1f 40 33 16 7e ?? 00 00 0a 7e ?? 00 00 04 28 ?? 00 00 06 80 06 00 00 04 2b 19 06 1f 20 33 14 7e ?? 00 00 0a 7e}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Crysan_AIBB_2147948014_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Crysan.AIBB!MTB"
        threat_id = "2147948014"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Crysan"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "18"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "VirtualAllocEx" ascii //weight: 1
        $x_1_2 = "WriteProcessMemory" ascii //weight: 1
        $x_1_3 = "CreateRemoteThread" ascii //weight: 1
        $x_10_4 = "QzpcUHJvZ3JhbURhdGFcTWljcm9zb2Z0XEVkZ2VVcGRhdGUuZGxs" wide //weight: 10
        $x_5_5 = "c2lob3N0" wide //weight: 5
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Crysan_ANSC_2147949343_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Crysan.ANSC!MTB"
        threat_id = "2147949343"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Crysan"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {b7 13 0e 11 0d 11 0e 61 11 05 61 13 0f 07 11 0f 28 ?? 02 00 0a 28 ?? 02 00 0a 28 ?? 00 00 0a 0b 11 0c 17 d6 13 0c 11 0c 11 0b 31 b1}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Crysan_ACS_2147952861_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Crysan.ACS!MTB"
        threat_id = "2147952861"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Crysan"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {0a 16 0b 2b 21 04 07 03 07 91 02 7b ?? 00 00 04 06 91 61 d2 9c 06 17 58 02 7b ?? 00 00 04 8e 69 5d 0a 07 17 58 0b 07 03 8e 69}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Crysan_AVR_2147954603_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Crysan.AVR!MTB"
        threat_id = "2147954603"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Crysan"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {11 04 17 da 13 0d 18 13 0e 2b 1a 11 05 11 0e 11 05 11 0e 17 da 96 11 05 11 0e 18 da 96 d6 9f 11 0e 17 d6 13 0e 11 0e 11 0d}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Crysan_ANS_2147955675_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Crysan.ANS!MTB"
        threat_id = "2147955675"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Crysan"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {18 5b 17 da 17 d6 8d ?? 00 00 01 0c 07 16 8c ?? 00 00 01 08 17 28 ?? 00 00 0a 18 da 8c ?? 00 00 01 17 8c ?? 00 00 01 12 03 12 01 28 ?? 00 00 0a 13 04 11 04 2c 4a 08 07 28 ?? 00 00 0a 72 ?? f8 03 70 02 18 8c ?? 00 00 01 07 28}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Crysan_AYB_2147958367_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Crysan.AYB!MTB"
        threat_id = "2147958367"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Crysan"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_5_1 = {ec bf fc 02 fa 91 2f 87 2a e5 c8 49 7f 8a b7 3d de 7f 97 75 bf 6d 7c 0b cc bc e1 3a fd f8 ef 6f b8 40 ae 9d 3a 9e e2 75 c6 33 d8 fe fa bb d6 fd 5b 60 ea f7 27 8c eb f7 c2 4f ba 60 e7 d7 09 3b de b2 e5 53 2f a5 f9 c5 9c 51 fd 9e 4f e4 fe ae}  //weight: 5, accuracy: High
        $x_3_2 = "ynqekxomipxues.Resources" ascii //weight: 3
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Crysan_PGZ_2147959296_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Crysan.PGZ!MTB"
        threat_id = "2147959296"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Crysan"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "12"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {07 09 06 09 91 08 09 08 8e 69 5d 91 61 d2 9c 08 09 08 8e 69 5d 08 09 08 8e 69 5d 91 17 58 20 ?? ?? ?? 00 5d d2 9c 00 09 17 58 0d 09 06 8e 69 fe 04 13 04 11 04 2d c8}  //weight: 10, accuracy: Low
        $x_1_2 = {00 02 28 08 00 00 0a 0a 06 8e 69}  //weight: 1, accuracy: High
        $x_1_3 = "FromBase64String" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


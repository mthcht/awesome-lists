rule Trojan_MSIL_Disco_DA_2147805215_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Disco.DA!MTB"
        threat_id = "2147805215"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Disco"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "RenewableCheat" ascii //weight: 1
        $x_1_2 = "//cdn.discordapp.com/attachments/" ascii //weight: 1
        $x_1_3 = "IsDebuggerPresent" ascii //weight: 1
        $x_1_4 = "ToBase64String" ascii //weight: 1
        $x_1_5 = "DownloadFile" ascii //weight: 1
        $x_1_6 = "GetTempPath" ascii //weight: 1
        $x_1_7 = "LoopA" ascii //weight: 1
        $x_1_8 = "LoopB" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Disco_DB_2147805216_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Disco.DB!MTB"
        threat_id = "2147805216"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Disco"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "UHJlbWl1bSBTcDAwZmVyKg==" ascii //weight: 1
        $x_1_2 = "_Encrypted$" ascii //weight: 1
        $x_1_3 = "CryptoObfuscator" ascii //weight: 1
        $x_1_4 = "IsDebuggerPresent" ascii //weight: 1
        $x_1_5 = "ToBase64String" ascii //weight: 1
        $x_1_6 = "DownloadFile" ascii //weight: 1
        $x_1_7 = "CreateInstance" ascii //weight: 1
        $x_1_8 = "Activator" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Disco_RE_2147841118_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Disco.RE!MTB"
        threat_id = "2147841118"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Disco"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_5_1 = {0a 2b 14 00 11 04 17 58 13 04 11 04 09 8e 69 fe 04 13 05 11 05 2d 97 06 0c 2b 00 08 2a}  //weight: 5, accuracy: High
        $x_1_2 = "supersex.exe" wide //weight: 1
        $x_1_3 = "SendMessageToDiscord" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Disco_RE_2147841118_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Disco.RE!MTB"
        threat_id = "2147841118"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Disco"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_5_1 = "https://discord.com/api/webhooks/1063358330103402506/j_aAfDqLgeMgZNFaOdYw1e84wg2" wide //weight: 5
        $x_2_2 = "testing_web.pdb" ascii //weight: 2
        $x_2_3 = "$1265309a-3806-4a29-82cf-294b3f2711e5" ascii //weight: 2
        $x_1_4 = "take_screenshot" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Disco_NEAA_2147841887_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Disco.NEAA!MTB"
        threat_id = "2147841887"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Disco"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "14"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {11 02 18 5b 8d ?? 00 00 01 13 03 38 dd ff ff ff 11 03 11 06 18 5b 11 01 11 06 18 6f ?? 00 00 0a 1f 10 28 05 00 00 0a 9c}  //weight: 10, accuracy: Low
        $x_2_2 = "Ooxith" ascii //weight: 2
        $x_2_3 = "Pmluxjjwfxk.bmp" wide //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Disco_DAC_2147842017_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Disco.DAC!MTB"
        threat_id = "2147842017"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Disco"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_3_1 = {11 04 18 6f ?? 00 00 0a 11 04 0c 28 ?? 00 00 0a 08 6f ?? 00 00 0a 07 16 07 8e 69 6f ?? 00 00 0a 6f ?? 00 00 0a 28 ?? 00 00 0a 0a de 22 7e ?? 00 00 04 18 9a 80 ?? 00 00 04 2b a1}  //weight: 3, accuracy: Low
        $x_1_2 = "CreateDecryptor" ascii //weight: 1
        $x_1_3 = "FromBase64String" ascii //weight: 1
        $x_1_4 = "a62f44d77141426e9fa216f32d0cd0c1" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Disco_NEAC_2147842211_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Disco.NEAC!MTB"
        threat_id = "2147842211"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Disco"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "12"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {0a 0b 07 09 6f ?? 00 00 0a 13 04 06 11 04 6f ?? 00 00 0a 06 18 6f ?? 00 00 0a 02 0c 06 6f ?? 00 00 0a 08 16 08 8e 69 6f ?? 00 00 0a 13 05 de 0e}  //weight: 10, accuracy: Low
        $x_1_2 = "CreateDecryptor" ascii //weight: 1
        $x_1_3 = "TripleDESCryptoServiceProvider" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Disco_GFM_2147842592_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Disco.GFM!MTB"
        threat_id = "2147842592"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Disco"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "cdn.discordapp.com/attachments" ascii //weight: 1
        $x_1_2 = "Zeus.exe" ascii //weight: 1
        $x_1_3 = "api.f3d.at/v1/obfuscate.php?key=" ascii //weight: 1
        $x_1_4 = "LPQdVs7C9jgSKHhdoC" ascii //weight: 1
        $x_1_5 = "OOmUsk2TTam2uE0SZ2.wMJVgumsf2DCfqlaKq" ascii //weight: 1
        $x_1_6 = "FromBase64String" ascii //weight: 1
        $x_1_7 = "CreateDecryptor" ascii //weight: 1
        $x_1_8 = "furkisgay" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Disco_SP_2147844275_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Disco.SP!MTB"
        threat_id = "2147844275"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Disco"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {07 08 9a 0d 09 28 ?? ?? ?? 0a 09 28 ?? ?? ?? 0a 2c 0b 09 28 ?? ?? ?? 06 80 0a 00 00 04 08 17 58 0c 08 07 8e 69 32}  //weight: 1, accuracy: Low
        $x_1_2 = "DonaldGrabber" ascii //weight: 1
        $x_1_3 = "DonaldGrabber.dll" ascii //weight: 1
        $x_1_4 = "Succesfully injected!" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Disco_SK_2147894241_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Disco.SK!MTB"
        threat_id = "2147894241"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Disco"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {00 07 09 07 8e 69 5d 02 07 09 07 8e 69 5d 91 08 09 08 6f ?? ?? ?? 0a 5d 6f ?? ?? ?? 0a 61 28 ?? ?? ?? 0a d2 07 09 17 58 07 8e 69 5d 91 28 ?? ?? ?? 0a d2 59 20 00 01 00 00 58 28 ?? ?? ?? 06 28 ?? ?? ?? 0a d2 9c 00 09 15 58 0d 09 16 fe 04 16 fe 01 13 07 11 07 2d a8}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Disco_SPQF_2147899642_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Disco.SPQF!MTB"
        threat_id = "2147899642"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Disco"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_4_1 = {06 03 07 6f ?? ?? ?? 0a 04 61 d1 6f ?? ?? ?? 0a 26 00 07 17 58 0b 07 03 6f ?? ?? ?? 0a fe 04 0c 08 2d dc}  //weight: 4, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Disco_MVA_2147903549_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Disco.MVA!MTB"
        threat_id = "2147903549"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Disco"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {02 28 1a 00 00 0a 72 7d 00 00 70 72 8b 00 00 70 28 0a 00 00 06 28 1b 00 00 0a 1b 28 0e 00 00 06 14 16 28 1c 00 00 0a 0a de 05}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Disco_GNW_2147904163_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Disco.GNW!MTB"
        threat_id = "2147904163"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Disco"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "12"
        strings_accuracy = "High"
    strings:
        $x_5_1 = {0b 07 17 2e 08 07 20 01 80 ff ff 33 23 7e 01 00 00 04 06 0c 12 02 fe}  //weight: 5, accuracy: High
        $x_5_2 = {80 01 00 00 04 06 17 58 0a 06 20 ff 00 00 00 32 be}  //weight: 5, accuracy: High
        $x_1_3 = "cdn.discordapp.com/attachments/961905736139554876" ascii //weight: 1
        $x_1_4 = "startkeylogger" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Disco_MK_2147961465_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Disco.MK!MTB"
        threat_id = "2147961465"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Disco"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "35"
        strings_accuracy = "High"
    strings:
        $x_25_1 = {02 28 18 00 00 06 0c 1a 08 8e 69 58 8d 16 00 00 01 0d 08 8e 69 28 4b 00 00 0a 09 16 6f 4f 00 00 0a 08 09 1a 6f 4f 00 00 0a 7e 05 00 00 04 09 16 09 8e 69 6f 4a 00 00 0a}  //weight: 25, accuracy: High
        $x_10_2 = {28 2d 00 00 06 26 25 11 06 28 29 00 00 06 26 11 05 28 2b 00 00 06 26 28 2c 00 00 06 26 7e 48 00 00 0a 11 04 28 25 00 00 06 26 73 49 00 00 0a 13 0a}  //weight: 10, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


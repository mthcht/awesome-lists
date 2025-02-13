rule PWS_MSIL_Dcstl_GG_2147755910_0
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:MSIL/Dcstl.GG!MTB"
        threat_id = "2147755910"
        type = "PWS"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Dcstl"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "33"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "Roaming\\Discord" ascii //weight: 10
        $x_10_2 = "[\\w-]{24}\\.[\\w-]{6}\\.[\\w-]{27}" ascii //weight: 10
        $x_10_3 = "mfa\\.[\\w-]{84}" ascii //weight: 10
        $x_1_4 = "Local\\Google\\Chrome\\User Data\\Default" ascii //weight: 1
        $x_1_5 = "Roaming\\Opera Software\\Opera Stable" ascii //weight: 1
        $x_1_6 = "Local\\BraveSoftware\\Brave-Browser\\User Data\\Default" ascii //weight: 1
        $x_1_7 = "\\AppData\\" ascii //weight: 1
        $x_1_8 = "\\Local Storage\\leveldb" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((3 of ($x_10_*) and 3 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule PWS_MSIL_Dcstl_GA_2147755911_0
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:MSIL/Dcstl.GA!MTB"
        threat_id = "2147755911"
        type = "PWS"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Dcstl"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "21"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "Stealer" ascii //weight: 10
        $x_10_2 = "https://discordapp.com/api/webhooks/" ascii //weight: 10
        $x_10_3 = "\\Google\\Chrome\\User Data\\Default\\Local Storage\\leveldb\\" ascii //weight: 10
        $x_1_4 = "\\discord\\Local Storage\\leveldb\\" ascii //weight: 1
        $x_1_5 = "\\LDISCORD\\" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_10_*) and 1 of ($x_1_*))) or
            ((3 of ($x_10_*))) or
            (all of ($x*))
        )
}

rule PWS_MSIL_Dcstl_GB_2147755912_0
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:MSIL/Dcstl.GB!MTB"
        threat_id = "2147755912"
        type = "PWS"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Dcstl"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "32"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "DiscordTokenGrabber" ascii //weight: 10
        $x_10_2 = "smtp.gmail.com" ascii //weight: 10
        $x_10_3 = "DiscordTokeen by" ascii //weight: 10
        $x_1_4 = "\\discord\\Local Storage\\leveldb\\" ascii //weight: 1
        $x_1_5 = "SmtpDeliveryMethod" ascii //weight: 1
        $x_1_6 = "NetworkCredential" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((3 of ($x_10_*) and 2 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule PWS_MSIL_Dcstl_GD_2147755913_0
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:MSIL/Dcstl.GD!MTB"
        threat_id = "2147755913"
        type = "PWS"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Dcstl"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "12"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "\\discord\\Local Storage\\leveldb\\" ascii //weight: 10
        $x_1_2 = "DiscordTokeen by NYAN CAT" ascii //weight: 1
        $x_1_3 = "SmtpDeliveryMethod" ascii //weight: 1
        $x_1_4 = "https://discordapp.com/api/webhooks/" ascii //weight: 1
        $x_1_5 = "\"([A-Za-z0-9_\\./\\\\-]){59}\"" ascii //weight: 1
        $x_1_6 = "[\\w-]{24}\\.[\\w-]{6}\\.[\\w-]{27}" ascii //weight: 1
        $x_1_7 = "mfa\\.[\\w-]{84}" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_10_*) and 2 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule PWS_MSIL_Dcstl_PDA_2147827838_0
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:MSIL/Dcstl.PDA!MTB"
        threat_id = "2147827838"
        type = "PWS"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Dcstl"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {0a 0b 1b 28 ?? ?? ?? 0a 72 ?? ?? ?? 70 28 ?? ?? ?? 0a 0c 72 ?? ?? ?? 70 0d 72 ?? ?? ?? 70 72 ?? ?? ?? 70 7e ?? ?? ?? 0a 28 ?? ?? ?? 0a 28 ?? ?? ?? 0a 72 ?? ?? ?? 70 28 ?? ?? ?? 0a 0d de 15}  //weight: 1, accuracy: Low
        $x_1_2 = {01 25 16 72 ?? ?? ?? 70 a2 16 6f ?? ?? ?? 0a 16 9a 13 16 11 16 28 ?? ?? ?? 0a 1b 28 ?? ?? ?? 2b 28 ?? ?? ?? 2b 14 16 28 ?? ?? ?? 0a 28 ?? ?? ?? 0a 13 17 11 15 11 17 28}  //weight: 1, accuracy: Low
        $x_1_3 = {31 0d 11 04 28 ?? ?? ?? 0a 16 28 ?? ?? ?? 0a 72 ?? ?? ?? 70 20 ?? ?? ?? 00 73 ?? ?? ?? 0a 13 05 11 05}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule PWS_MSIL_Dcstl_PDC_2147827839_0
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:MSIL/Dcstl.PDC!MTB"
        threat_id = "2147827839"
        type = "PWS"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Dcstl"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {0a 26 07 28 ?? ?? ?? 0a 07 28 ?? ?? ?? 0a 0c 0d 16 13}  //weight: 1, accuracy: Low
        $x_2_2 = {0a 26 08 7e ?? ?? ?? 04 72 ?? ?? ?? 70 08 6f ?? ?? ?? 0a 28 ?? ?? ?? 0a 6f ?? ?? ?? 0a 26 07 17 58 0b 07 06 8e 69 32 bd}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule PWS_MSIL_Dcstl_PDF_2147827841_0
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:MSIL/Dcstl.PDF!MTB"
        threat_id = "2147827841"
        type = "PWS"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Dcstl"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {0a 25 0a 0b 72 ?? ?? ?? 70 0c 72 ?? ?? ?? 70 72 ?? ?? ?? 70 73 ?? ?? ?? 0a 28 ?? ?? ?? 0a 0d 73 ?? ?? ?? 0a 13 04}  //weight: 2, accuracy: Low
        $x_1_2 = {13 05 07 28 ?? ?? ?? 0a 13 06 11 05 28 ?? ?? ?? 0a 09 6f ?? ?? ?? 0a 16 28 ?? ?? ?? 0a 09 6f ?? ?? ?? 0a 8e 69}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule PWS_MSIL_Dcstl_PDG_2147827842_0
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:MSIL/Dcstl.PDG!MTB"
        threat_id = "2147827842"
        type = "PWS"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Dcstl"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {02 1f 0f 28 ?? ?? ?? 2b 28 ?? ?? ?? 2b 0a 1f 1a 28 ?? ?? ?? 0a 72 ?? ?? ?? 70 ?? ?? ?? 00 0a 28 ?? ?? ?? 06 73 ?? ?? ?? 0a 20 ?? ?? ?? 00 02 19 28 ?? ?? ?? 2b 1f 0c 28 ?? ?? ?? 2b 28 ?? ?? ?? 2b 14 73 ?? ?? ?? 0a 0b 73 ?? ?? ?? 0a 73 ?? ?? ?? 0a 0c 08 16 07 6f ?? ?? ?? 0a 00 08 06 8e 69 6f ?? ?? ?? 0a 8d 5b 00 00 01 0d 08 09 08 06 16}  //weight: 1, accuracy: Low
        $x_1_2 = {04 0a 06 2c 08 00 28 ?? ?? ?? 06 00 00 7e ?? ?? ?? 04 0b 07 2c 0c}  //weight: 1, accuracy: Low
        $x_1_3 = {04 0a 06 2c 32 00 7e ?? ?? ?? 04 73 ?? ?? ?? 06 0b 07 72}  //weight: 1, accuracy: Low
        $x_1_4 = {04 0a 06 2c 32 00 7e ?? ?? ?? 04 73 ?? ?? ?? 06 0b 07 72 ?? ?? ?? 70 ?? ?? ?? 00 06 72 ?? ?? ?? 70 28 ?? ?? ?? 06 28 ?? ?? ?? 0a 6f ?? ?? ?? 06 26 00 38 ?? ?? ?? 00 00 72 ?? ?? ?? 70 28 ?? ?? ?? 06 0c 08 28 ?? ?? ?? 0a 13 0f 11 0f}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule PWS_MSIL_Dcstl_PDK_2147827843_0
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:MSIL/Dcstl.PDK!MTB"
        threat_id = "2147827843"
        type = "PWS"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Dcstl"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {0a 12 02 fe ?? ?? ?? 00 01 12 02 28 ?? ?? ?? 0a 25 2d 06 26 72 ?? ?? ?? 70 7d ?? ?? ?? 0a 12 02 02 7b ?? ?? ?? 04 6f ?? ?? ?? 0a 25 2d 06 26}  //weight: 1, accuracy: Low
        $x_1_2 = {0a 16 0b 2b 1f 06 07 9a 0c 02 7b ?? ?? ?? 04 6f ?? ?? ?? 0a 08 6f ?? ?? ?? 0a 6f ?? ?? ?? 0a 26 07 17 58 0b}  //weight: 1, accuracy: Low
        $x_1_3 = {06 07 9a 6f ?? ?? ?? 0a 07 17 58 0b 07 06 8e 69 32 ee}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule PWS_MSIL_Dcstl_PDM_2147827844_0
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:MSIL/Dcstl.PDM!MTB"
        threat_id = "2147827844"
        type = "PWS"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Dcstl"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {70 03 6f 13 ?? ?? 0a 00 02 7b ?? ?? ?? 04 02 28 ?? ?? ?? 06 7e ?? ?? ?? 04 6f ?? ?? ?? 0a 26 2a}  //weight: 1, accuracy: Low
        $x_1_2 = {02 7b 01 00 00 04 6f 15 00 00 0a 00 2a}  //weight: 1, accuracy: High
        $x_1_3 = {06 00 06 72 ?? ?? ?? 70 02 16 9a 72 ?? ?? ?? 70 28 ?? ?? ?? 0a 6f ?? ?? ?? 06 00 00 de 0b}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule PWS_MSIL_Dcstl_ABN_2147828469_0
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:MSIL/Dcstl.ABN!MTB"
        threat_id = "2147828469"
        type = "PWS"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Dcstl"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "Low"
    strings:
        $x_4_1 = {0a 0a 06 72 6b ?? ?? 70 17 6f ?? ?? ?? 0a 0b 72 ?? ?? ?? 70 0c 00 07 0d 16 13 04 2b 7c 31 00 02 7b ?? ?? ?? 04 72 ?? ?? ?? 70 28 ?? ?? ?? 0a 73 18}  //weight: 4, accuracy: Low
        $x_1_2 = "GetFolderPath" ascii //weight: 1
        $x_1_3 = "dWebHook" ascii //weight: 1
        $x_1_4 = "UploadValues" ascii //weight: 1
        $x_1_5 = "discordValues" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule PWS_MSIL_Dcstl_PDB_2147830861_0
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:MSIL/Dcstl.PDB!MTB"
        threat_id = "2147830861"
        type = "PWS"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Dcstl"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {21 52 26 2e 43 3d ?? ?? ?? 7c 2a 33 bf ba 84 9b c0 4f 0d d1 58}  //weight: 2, accuracy: Low
        $x_1_2 = {f6 c5 cc 67 6a 55}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule PWS_MSIL_Dcstl_PDH_2147830862_0
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:MSIL/Dcstl.PDH!MTB"
        threat_id = "2147830862"
        type = "PWS"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Dcstl"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {11 07 11 08 6f ?? ?? ?? 0a 13 09 00 07 72 ?? ?? ?? 70 11 09 8c ?? ?? ?? 01 08 25 17 58 0c 17 5f 2c 07 72 ?? ?? ?? 70 2b 05 72 ?? ?? ?? 70 6f ?? ?? ?? 0a 26 00 11 08 17 58 13 08 11 08 11 07 6f ?? ?? ?? 0a 32 ba}  //weight: 1, accuracy: Low
        $x_1_2 = {01 0a 06 72 ?? ?? ?? 70 6f ?? ?? ?? 0a 00 06 72 ?? ?? ?? 70 6f ?? ?? ?? 0a 00 06 6f ?? ?? ?? 0a 72 ?? ?? ?? 70 7e ?? ?? ?? 04 6f ?? ?? ?? 0a 00 14 0b}  //weight: 1, accuracy: Low
        $x_1_3 = {0a 0b 07 6f ?? ?? ?? 0a 0c 08 0d 2b 00 09 2a}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule PWS_MSIL_Dcstl_PDJ_2147830863_0
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:MSIL/Dcstl.PDJ!MTB"
        threat_id = "2147830863"
        type = "PWS"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Dcstl"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {11 09 2c 2a 00 11 08 6f ?? ?? ?? 0a 17 8d ?? ?? ?? 01 25 16 72 ?? ?? ?? 70 a2 16 6f ?? ?? ?? 0a 17 9a 28 1c ?? ?? ?? 28 ?? ?? ?? 06 0a 00 00 11 04 17 58}  //weight: 1, accuracy: Low
        $x_1_2 = {0a 0c 08 16 07 6f ?? ?? ?? 0a 00 08 06 8e 69 6f ?? ?? ?? 0a 8d ?? ?? ?? 01 0d 08 09}  //weight: 1, accuracy: Low
        $x_1_3 = {2c 02 2b 2f 16 72 ?? ?? ?? 70 d0 ?? ?? ?? 02 28 ?? ?? ?? 0a 17 8d ?? ?? ?? 01 25 16 16 14 28 ?? ?? ?? 0a a2 28 ?? ?? ?? 0a 28 ?? ?? ?? 0a 80 ?? ?? ?? 04 7e ?? ?? ?? 04 7b ?? ?? ?? 0a 7e ?? ?? ?? 04 7e ?? ?? ?? 04 2c 02 2b 2f}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule PWS_MSIL_Dcstl_PDO_2147830864_0
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:MSIL/Dcstl.PDO!MTB"
        threat_id = "2147830864"
        type = "PWS"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Dcstl"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {70 02 7b 01 ?? ?? 04 72 ?? ?? ?? 70 28 ?? ?? ?? 0a 7d ?? ?? ?? 04 02 7b ?? ?? ?? 04 72 ?? ?? ?? 70 28 ?? ?? ?? 0a 28 ?? ?? ?? 0a 26 2a}  //weight: 1, accuracy: Low
        $x_1_2 = {0d 16 13 04 2b 20 09 11 04 9a 13 05 00 11 05 11 05 02 03 6f ?? ?? ?? 0a 17 28 ?? ?? ?? 0a 00 00 11 04 17 58 13 04 11 04 09 8e 69 32 d9}  //weight: 1, accuracy: Low
        $x_1_3 = {0a 26 72 01 ?? ?? ?? 02 7b ?? ?? ?? 04 72 ?? ?? ?? 70 28 ?? ?? ?? 0a 02 7b ?? ?? ?? 04 72 ?? ?? ?? 70 28 ?? ?? ?? 0a 28 ?? ?? ?? 06 00 2a}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule PWS_MSIL_Dcstl_PDQ_2147830865_0
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:MSIL/Dcstl.PDQ!MTB"
        threat_id = "2147830865"
        type = "PWS"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Dcstl"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {11 0b 72 b7 ?? ?? ?? 72 ?? ?? ?? 70 02 7b ?? ?? ?? 04 6f ?? ?? ?? 0a 26 00 de 0d 11 0b 2c 08 11 0b 6f ?? ?? ?? 0a 00 dc}  //weight: 1, accuracy: Low
        $x_1_2 = {02 1f 1a 28 ?? ?? ?? 0a 7d ?? ?? ?? 04 02 1f 28 28 ?? ?? ?? 0a 7d ?? ?? ?? 04 02 73 ?? ?? ?? 0a 7d ?? ?? ?? 04 02 28 ?? ?? ?? 0a 00 2a}  //weight: 1, accuracy: Low
        $x_1_3 = {06 0a 06 72 ?? ?? ?? 70 6f ?? ?? ?? 06 00 06 72 ?? ?? ?? 70 6f ?? ?? ?? 06 00 2a}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule PWS_MSIL_Dcstl_PDR_2147830866_0
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:MSIL/Dcstl.PDR!MTB"
        threat_id = "2147830866"
        type = "PWS"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Dcstl"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {13 04 11 04 13 07 11 07 39 ?? ?? ?? 00 00 09 72 ?? ?? ?? 70 28 ?? ?? ?? 0a 6f ?? ?? ?? 0a 17 6f}  //weight: 1, accuracy: Low
        $x_1_2 = {07 06 8e 69 6a 6f ?? ?? ?? 0a 00 07 6f ?? ?? ?? 0a 0c 08 06 16 06 8e 69 6f ?? ?? ?? 0a 00 08 6f ?? ?? ?? 0a}  //weight: 1, accuracy: Low
        $x_1_3 = {25 2d 17 26 7e ?? ?? ?? 04 fe ?? ?? ?? ?? 06 73 ?? ?? ?? 0a 25 80 ?? ?? ?? 04 73 ?? ?? ?? 0a 0b 07 6f ?? ?? ?? 0a 00 07 1a 6f 2a 00 00 0a 00 00 06 17 58 0a 06 7e 0c 00 00 04 fe 02 16 fe 01 0c 08 2d b7}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule PWS_MSIL_Dcstl_PDU_2147830867_0
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:MSIL/Dcstl.PDU!MTB"
        threat_id = "2147830867"
        type = "PWS"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Dcstl"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {0c 29 01 00 48 89 4c 24 08 48 83 ec 38 b9 17 00 00 00 ff ?? ?? ?? ?? 00 85 c0 74 07 b9 02 00 00 00 cd 29 48 8d 0d 06 8c 02 00 e8}  //weight: 1, accuracy: Low
        $x_1_2 = {48 8b 85 c8 04 00 00 48 89 44 24 60 c7 44 24 50 15 00 00 40 c7 44 24 54 01 00 00 00 ff ?? ?? ?? ?? 00 83 f8 01 48 8d 44 24 50 48 89}  //weight: 1, accuracy: Low
        $x_1_3 = {48 8b c4 48 ?? ?? ?? 48 ?? ?? ?? 48 ?? ?? ?? 48 ?? ?? ?? 41 56 48 ?? ?? ?? 00 00 00 48 8d 48 88}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule PWS_MSIL_Dcstl_PDV_2147830868_0
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:MSIL/Dcstl.PDV!MTB"
        threat_id = "2147830868"
        type = "PWS"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Dcstl"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {06 25 02 6f ?? ?? ?? 06 00 0a 06 0b 07 28 ?? ?? ?? 0a 0c 72 ?? ?? ?? 70 08 28 ?? ?? ?? 0a 00 2a}  //weight: 1, accuracy: Low
        $x_1_2 = {2e 17 58 13 2e 11 2b 73 ?? ?? ?? 06 13 30 11 30 11 2c 6f ?? ?? ?? 06 26 72 ?? ?? ?? 70 12 2e 28}  //weight: 1, accuracy: Low
        $x_1_3 = {13 0b 2b 27 11 0b 6f ?? ?? ?? 0a 13 0c 00 00 11 0c 6f ?? ?? ?? 0a 00 7e ?? ?? ?? 04 28 ?? ?? ?? 0a 00 00 de 05}  //weight: 1, accuracy: Low
        $x_1_4 = {13 1e 12 1e 28 ?? ?? ?? 0a a2 28 ?? ?? ?? 0a 28 ?? ?? ?? 0a 00 72 ?? ?? ?? 70 28 23}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule PWS_MSIL_Dcstl_PDT_2147831350_0
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:MSIL/Dcstl.PDT!MTB"
        threat_id = "2147831350"
        type = "PWS"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Dcstl"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {70 0a 72 f4 ?? ?? ?? 28 ?? ?? ?? 0a 6f ?? ?? ?? 0a 28 ?? ?? ?? 0a 0b 06 72 ?? ?? ?? 70 72 ?? ?? ?? 70 07 28 ?? ?? ?? 06 00 2a}  //weight: 1, accuracy: Low
        $x_1_2 = {0a 06 72 14 ?? ?? ?? 04 6f ?? ?? ?? 0a 00 06 72 ?? ?? ?? 70 03 6f ?? ?? ?? 0a 00 06 72 ?? ?? ?? 70 05 6f ?? ?? ?? 0a 00 73 ?? ?? ?? 0a 02 06 28 ?? ?? ?? 0a 26 2a}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule PWS_MSIL_Dcstl_ABR_2147832743_0
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:MSIL/Dcstl.ABR!MTB"
        threat_id = "2147832743"
        type = "PWS"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Dcstl"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {07 16 73 92 ?? ?? 0a 0c 73 ?? ?? ?? 0a 0d 08 09 28 1e ?? ?? 06 09 16 6a 6f ?? ?? ?? 0a 09 13 04 de 1c 08 2c 06 08 6f ?? ?? ?? 0a dc}  //weight: 2, accuracy: Low
        $x_2_2 = {02 6f 96 00 00 0a d4 8d 63 00 00 01 0a 02 06 16 06 8e 69 6f 8e 00 00 0a 26 06 2a}  //weight: 2, accuracy: High
        $x_1_3 = "GetManifestResourceStream" ascii //weight: 1
        $x_1_4 = "DBTest.Properties.Resources" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule PWS_MSIL_Dcstl_PDW_2147836138_0
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:MSIL/Dcstl.PDW!MTB"
        threat_id = "2147836138"
        type = "PWS"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Dcstl"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {06 0a 72 95 ?? ?? ?? 0b 28 ?? ?? ?? 06 72 ?? ?? ?? 70 28 ?? ?? ?? 0a 0c 73 16}  //weight: 1, accuracy: Low
        $x_1_2 = {0a 13 04 08 28 ?? ?? ?? 0a 13 05 11 04 11 05 16 11 05 8e 69 73 ?? ?? ?? 0a 72 ?? ?? ?? 70 06 72}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule PWS_MSIL_Dcstl_PDX_2147844890_0
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:MSIL/Dcstl.PDX!MTB"
        threat_id = "2147844890"
        type = "PWS"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Dcstl"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {0a 07 11 05 9a 6f ?? ?? ?? 0a 2d 17 11 04}  //weight: 1, accuracy: Low
        $x_1_2 = {0a 0c 12 02 28 ?? ?? ?? 0a 28 ?? ?? ?? 0a 6f ?? ?? ?? 0a 0c 12 02}  //weight: 1, accuracy: Low
        $x_1_3 = {2c 02 17 2a 28 ?? ?? ?? 0a 72 ?? ?? ?? 70 28 ?? ?? ?? 0a 2c 38 28}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


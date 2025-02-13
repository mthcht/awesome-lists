rule TrojanDownloader_Linux_Mirai_D_2147757138_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Linux/Mirai.D!MTB"
        threat_id = "2147757138"
        type = "TrojanDownloader"
        platform = "Linux: Linux platform"
        family = "Mirai"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {44 80 99 8f 21 20 20 02 1c 00 a5 27 09 f8 20 03 10 00 06 24 10 00 bc 8f 0f 00 41 04 21 80 40 00 18 80 85 8f 48 80 99 8f ?? 06 a5 24 01 00 04 24 09 f8 20 03 ?? 00 06 24 10 00 bc 8f 00 00 00 00 54 80 99 8f 00 00 00 00 09 f8 20 03 23 20 10 00 10 00 bc 8f 00 00 00 00 18 80 85 8f 48 80 99 8f ?? 00 70 26 ?? 06 a5 24 21 20 20 02}  //weight: 1, accuracy: Low
        $x_1_2 = {47 45 54 20 2f [0-32] 2e 6d 70 73 6c 20 48 54 54 50 2f 31 2e 30 0d 0a}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_Linux_Mirai_A_2147767246_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Linux/Mirai.A!MTB"
        threat_id = "2147767246"
        type = "TrojanDownloader"
        platform = "Linux: Linux platform"
        family = "Mirai"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {4d 49 52 41 49 0a 00 00}  //weight: 1, accuracy: High
        $x_2_2 = {4e 49 46 0a 00 00 00 00 47 45 54 20 2f 62 69 6e 73 2f 6d 69 72 61 69 2e [0-5] 20 48 54 54 50 2f 31 2e 30 0d 0a 0d 0a 00 00 00 00 46 49 4e 0a 00}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_Linux_Mirai_AN_2147794410_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Linux/Mirai.AN"
        threat_id = "2147794410"
        type = "TrojanDownloader"
        platform = "Linux: Linux platform"
        family = "Mirai"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "User-Agent: Dark" ascii //weight: 1
        $x_1_2 = {63 64 20 2f 74 6d 70 3b 20 77 67 65 74 20 68 74 74 70 3a 2f 2f [0-40] 2e 73 68}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_Linux_Mirai_SB_2147808329_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Linux/Mirai.SB!xp"
        threat_id = "2147808329"
        type = "TrojanDownloader"
        platform = "Linux: Linux platform"
        family = "Mirai"
        severity = "Critical"
        info = "xp: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "hito antihoney airdropped" ascii //weight: 1
        $x_1_2 = "./dd load.wget" ascii //weight: 1
        $x_1_3 = {77 67 65 74 20 68 74 74 70 [0-32] 2f 73 77 72 67 69 75 68 67 75 68 77 72 67 75 69 77 65 74 75 2f ?? 70 63 20 2d 4f 20 2d 20 3e 20 64 64}  //weight: 1, accuracy: Low
        $x_1_4 = "chmod 777 cc" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_Linux_Mirai_A_2147815778_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Linux/Mirai.A!xp"
        threat_id = "2147815778"
        type = "TrojanDownloader"
        platform = "Linux: Linux platform"
        family = "Mirai"
        severity = "Critical"
        info = "xp: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "hito antihoney airdropped" ascii //weight: 1
        $x_1_2 = "./dd load.wget" ascii //weight: 1
        $x_1_3 = {77 67 65 74 20 68 74 74 70 [0-53] 20 2d 4f 20 2d 20 3e 20 64 64}  //weight: 1, accuracy: Low
        $x_1_4 = "chmod 777 cc" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_Linux_Mirai_B_2147818655_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Linux/Mirai.B!MTB"
        threat_id = "2147818655"
        type = "TrojanDownloader"
        platform = "Linux: Linux platform"
        family = "Mirai"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {47 45 54 20 2f 4d 6f 7a 69 2e ?? 20 48 54 54 50 2f}  //weight: 2, accuracy: Low
        $x_2_2 = {4d 6f 7a 69 0a 00 00 00 2f 70 72 6f 63 2f 73 65 6c 66 2f 63 6d 64 6c 69 6e 65 00 00 52 75 6e 6e 00}  //weight: 2, accuracy: High
        $x_1_3 = {24 04 00 01 24 06 00 05 24 42 07 ?? 03 20 f8 09 02 02 98 23 8f bc 00 10 00 00 28 21 8f 84 80 18 8f 99 80 68 24 84 07 ?? 03 20 f8 09 24 06 01 ed}  //weight: 1, accuracy: Low
        $x_1_4 = {01 00 04 24 05 00 06 24 ?? 07 42 24 09 f8 20 03 23 98 02 02 10 00 bc 8f 21 28 00 00 18 80 84 8f 68 80 99 8f ?? 07 84 24 09 f8 20 03 ed 01 06 24}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_2_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule TrojanDownloader_Linux_Mirai_C_2147819112_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Linux/Mirai.C!MTB"
        threat_id = "2147819112"
        type = "TrojanDownloader"
        platform = "Linux: Linux platform"
        family = "Mirai"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {00 4d 49 52 41 49 0a 00 [0-21] 4e 49 46 0a 00 [0-5] 47 45 54 20 2f [0-32] 20 48 54 54 50 2f 31 2e 30 0d 0a 0d 0a 00 [0-32] 46 49 4e 0a 00}  //weight: 1, accuracy: Low
        $x_1_2 = {00 4e 49 46 0a 00 [0-8] 47 45 54 20 2f 62 69 6e 73 2f [0-16] 2e [0-8] 20 48 54 54 50 2f 31 2e 30 0d 0a 55 73 65 72 2d 41 67 65 6e 74 3a 20 [0-16] 4d 69 72 61 69 0d 0a [0-16] 00 42 4f 41 54 0a 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule TrojanDownloader_Linux_Mirai_E_2147819356_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Linux/Mirai.E!MTB"
        threat_id = "2147819356"
        type = "TrojanDownloader"
        platform = "Linux: Linux platform"
        family = "Mirai"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {0a 00 47 45 54 20 2f [0-32] 20 48 54 54 50 2f 31 2e 30 0d 0a}  //weight: 1, accuracy: Low
        $x_1_2 = {48 78 00 10 48 6e ff ee 2f 03 61 ff ff ff fe ?? 24 00 4f ef 00 0c 6c 22 48 78 00 ?? 48 79 80 00 03 ?? 48 78 00 01 61 ff ff ff fe ?? 44 82 2f 02 61 ff ff ff fe ?? 4f ef 00 10 45 ea 00 ?? 2f 0a 48 79 80 00 03 ?? 2f 03 61 ff ff ff fe ?? 4f ef 00 0c b5 c0 67 0c 48 78 00 03 61 ff ff ff fe ?? 58 8f}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_Linux_Mirai_F_2147819357_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Linux/Mirai.F!MTB"
        threat_id = "2147819357"
        type = "TrojanDownloader"
        platform = "Linux: Linux platform"
        family = "Mirai"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {00 47 45 54 20 2f [0-32] 70 63 20 48 54 54 50 2f 31 2e 30 0d 0a}  //weight: 1, accuracy: Low
        $x_1_2 = {3c 80 10 00 38 84 ?? ?? 7f ?? ?? 78 7f ?? ?? 78 4b ff fe ?? 7f 83 e8 00 41 9e 00 0c 38 60 00 03 4b ff fd ?? 3b a0 00 00 38 81 00 08 38 a0 00 01 7f ?? ?? 78 4b ff fe ?? 2f 83 00 01 38 60 00 04 41 9e 00 08 4b ff fd ?? 89 61 00 08 57 a9 40 2e 3c 00 0d 0a 7d 3d 5b 78 60 00 0d 0a}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_Linux_Mirai_G_2147819818_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Linux/Mirai.G!MTB"
        threat_id = "2147819818"
        type = "TrojanDownloader"
        platform = "Linux: Linux platform"
        family = "Mirai"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {00 47 45 54 20 2f [0-16] 2f [0-16] 73 68 34 20 48 54 54 50 2f 31 2e 30}  //weight: 1, accuracy: Low
        $x_1_2 = {d5 0b 40 83 66 80 30 02 89 ?? d1 0b 41 03 e4 00 e8 ?? 9a 93 64 ?? d0 01 e6 ec 3a a3 65 0b 40 18 48 01 88 03 8d 04 e4 ?? d1 0b 41 09 00 a0 61 1b 28 ?? d1 10 38 ec 8b}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_Linux_Mirai_H_2147819819_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Linux/Mirai.H!MTB"
        threat_id = "2147819819"
        type = "TrojanDownloader"
        platform = "Linux: Linux platform"
        family = "Mirai"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {00 47 45 54 20 2f [0-32] 6d 69 70 73 20 48 54 54 50 2f 31 2e 30 0d 0a}  //weight: 1, accuracy: Low
        $x_1_2 = {8f 85 80 18 8f 99 80 ?? 26 70 00 ?? 24 a5 ?? ?? 02 20 20 21 03 20 f8 09 02 00 30 21 8f bc 00 10 10 50 00 07 00 00 80 21 8f 99 80 ?? 00 00 00 00 03 20 f8 09 24 04 00 03 8f bc 00 10 00 00 80 21 8f 99 80 ?? 02 20 20 21 27 a5 00 18 03 20 f8 09 24 06 00 01 8f bc 00 10 24 03 00 01 8f 99 80 ?? 10 43 00 04 24 04 00 04 03 20 f8 09}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_Linux_Mirai_B_2147828129_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Linux/Mirai.B!xp"
        threat_id = "2147828129"
        type = "TrojanDownloader"
        platform = "Linux: Linux platform"
        family = "Mirai"
        severity = "Critical"
        info = "xp: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {00 47 45 54 20 2f 70 65 69 6e 2e 61 72 6d 37 20 48 54 54 50}  //weight: 1, accuracy: High
        $x_1_2 = "bigbotPein" ascii //weight: 1
        $x_1_3 = "GET /pein.arm7 HTTP/1.0" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_Linux_Mirai_J_2147906808_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Linux/Mirai.J!MTB"
        threat_id = "2147906808"
        type = "TrojanDownloader"
        platform = "Linux: Linux platform"
        family = "Mirai"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {04 e0 2d e5 00 10 a0 e1 04 d0 4d e2 01 00 a0 e3 ad 00 00 eb 04 d0 8d e2 04 e0 9d e4 1e ff 2f e1 04 e0 2d e5 00 10 a0 e1 04 d0 4d e2 06 00 a0 e3 a5 00 00 eb 04 d0 8d e2 04 e0 9d e4 1e ff 2f e1}  //weight: 1, accuracy: High
        $x_1_2 = {0d c0 a0 e1 f0 00 2d e9 00 70 a0 e1 01 00 a0 e1 02 10 a0 e1 03 20 a0 e1 78 00 9c e8 00 00 00 ef f0 00 bd e8 01 0a 70 e3 0e f0 a0 31 ff ff ff ea}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_Linux_Mirai_K_2147917788_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Linux/Mirai.K!MTB"
        threat_id = "2147917788"
        type = "TrojanDownloader"
        platform = "Linux: Linux platform"
        family = "Mirai"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {54 00 a2 27 40 00 a2 af 40 00 a3 8f 00 00 00 00 04 00 62 24 40 00 a2 af 21 10 60 00 00 00 42 8c 00 00 00 00 3c 00 a2 af 40 00 a3 8f 00 00 00 00 04 00 62 24 40 00 a2 af 21 10 60 00 00 00 42 8c}  //weight: 1, accuracy: High
        $x_1_2 = {21 28 60 02 21 c8 00 02 09 f8 20 03 80 00 06 24 21 30 40 00 10 00 bc 8f 21 20 80 02 07 ?? ?? ?? 21 28 60 02 21 c8 40 02 09 f8 20 03 00 00 00 00 10 00 bc 8f f2 ?? ?? ?? 21 20 20 02}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


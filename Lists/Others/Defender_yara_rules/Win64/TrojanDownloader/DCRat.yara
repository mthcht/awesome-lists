rule TrojanDownloader_Win64_DCRat_A_2147845487_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win64/DCRat.A!MTB"
        threat_id = "2147845487"
        type = "TrojanDownloader"
        platform = "Win64: Windows 64-bit platform"
        family = "DCRat"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "C:\\Users\\%s\\AppData\\Roaming\\Microsoft\\Windows\\Start Menu\\Programs\\Startup\\Windows_Defender_Advanced_Threat_Protection" wide //weight: 2
        $x_2_2 = "C:\\Program Files\\Windows NT\\TableTextService" wide //weight: 2
        $x_2_3 = "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run" wide //weight: 2
        $x_2_4 = "://free1459.host.od.ua/" wide //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_Win64_DCRat_C_2147847844_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win64/DCRat.C!MTB"
        threat_id = "2147847844"
        type = "TrojanDownloader"
        platform = "Win64: Windows 64-bit platform"
        family = "DCRat"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {48 33 c4 48 89 45 f0 48 8d 15 ?? ?? 00 00 33 c9 ff 15 ?? 1f 00 00 48 8d 0d ?? 21 00 00 ff 15 ?? ?? 00 00 4c 8b f0}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_Win64_DCRat_D_2147896976_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win64/DCRat.D!MTB"
        threat_id = "2147896976"
        type = "TrojanDownloader"
        platform = "Win64: Windows 64-bit platform"
        family = "DCRat"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "://yaysem.ru.swtest.ru/fa.exe" wide //weight: 2
        $x_2_2 = "test.exe" wide //weight: 2
        $x_2_3 = "open" wide //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_Win64_DCRat_E_2147917329_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win64/DCRat.E!MTB"
        threat_id = "2147917329"
        type = "TrojanDownloader"
        platform = "Win64: Windows 64-bit platform"
        family = "DCRat"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {c6 44 24 38 00 48 c7 44 24 20 00 00 00 00 45 33 c9 4c 8d 44 24 30 33 c9 ff 15 ?? ?? 00 00 c7 44 24 28 00 00 00 00 48 c7 44 24 20 00 00 00 00 45 33 c9 4c 8d 05 96 20 00 00 48 8d 15 9b 20 00 00 33 c9 ff 15 ?? ?? 00 00 b9 23 00 00 00 ff 15 ?? ?? 00 00 66 85 c0 75 ?? b9 01 00 00 00 ff 15 ?? ?? 00 00 b9 ?? 00 00 00 ff 15 ?? ?? 00 00 66 85 c0}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_Win64_DCRat_F_2147917979_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win64/DCRat.F!MTB"
        threat_id = "2147917979"
        type = "TrojanDownloader"
        platform = "Win64: Windows 64-bit platform"
        family = "DCRat"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "Low"
    strings:
        $x_4_1 = {48 0f 47 54 24 50 48 c7 44 24 20 00 00 00 00 45 33 c9 33 c9 ff 15 ?? ?? ?? 00 c7 44 24 28 00 00 00 00 48 c7 44 24 20 00 00 00 00 45 33 c9 4c 8d 05 ?? ?? ?? 00 48 8d 15 ?? ?? ?? 00 33 c9 ff 15}  //weight: 4, accuracy: Low
        $x_2_2 = {b9 23 00 00 00 ff 15 ?? ?? ?? 00 66 85 c0 75}  //weight: 2, accuracy: Low
        $x_2_3 = {b9 01 00 00 00 ff 15 ?? ?? ?? 00 b9 23 00 00 00 ff 15}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_Win64_DCRat_G_2147918330_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win64/DCRat.G!MTB"
        threat_id = "2147918330"
        type = "TrojanDownloader"
        platform = "Win64: Windows 64-bit platform"
        family = "DCRat"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "Low"
    strings:
        $x_4_1 = {0f be 04 0f 48 ff c1 03 c3 69 d8 ?? ?? ?? ?? 8b c3 c1 e8 ?? 33 d8 48 3b ca}  //weight: 4, accuracy: Low
        $x_2_2 = {44 0f b6 c1 41 8d ?? ?? 0f b6 c8 41 8d ?? ?? 80 fa 19 41 0f 47 c8 41 ff c1 42 88 4c 14 ?? 45 8b d1 43 0f b7 04 4b 0f b6 c8 66 85 c0}  //weight: 2, accuracy: Low
        $x_2_3 = {0f b6 04 38 42 88 04 01 8b 84 24 ?? ?? ?? ?? ff c0 89 84 24}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_Win64_DCRat_H_2147919388_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win64/DCRat.H!MTB"
        threat_id = "2147919388"
        type = "TrojanDownloader"
        platform = "Win64: Windows 64-bit platform"
        family = "DCRat"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {33 d2 8d 4a 02 ff 15 ?? 2b 00 00 48 8b f0 c7 85 c0 01 00 00 38 02 00 00 48 8d 95 c0 01 00 00 48 8b c8 ff 15 ?? 2b 00 00 85 c0 0f ?? ?? ?? ?? ?? 48 8d 85 ec 01 00 00 49 8b cf 66 0f 1f 44 00 00 48 ff c1 66 83 3c 48 00 75 ?? 48 8b c3 48 83 7b 18 08 72 ?? 48 8b 03 4c 8b 43 10 4c 3b c1 75 ?? 48 8d 95 ec 01 00 00 4d 85 c0 74 ?? 0f 1f 40 00 0f b7 0a 66 39 08 75 ?? 48 83 c0 02 48 83 c2 02 49 83 e8 01 75 ea 44 8b 85 c8 01 00 00 33 d2 8d 4a 01 ff 15 ?? 2b 00 00 48 8b f8 48 85 c0 74 ?? 33 d2 48 8b c8 ff 15 ?? 2b 00 00 48 8b cf ff ?? 6c 2b 00 00 48 8d 95 c0 01 00 00 48 8b ce ff 15 ?? 2b 00 00 85 c0 0f}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


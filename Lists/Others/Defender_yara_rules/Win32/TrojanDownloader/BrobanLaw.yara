rule TrojanDownloader_Win32_BrobanLaw_A_2147692505_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/BrobanLaw.A"
        threat_id = "2147692505"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "BrobanLaw"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {c7 45 f4 01 00 00 00 8b 45 fc 8b 55 f4 33 db 8a 5c 10 ff 03 5d f8 8b c3 33 d2 52 50 8d 45 e8 e8 ?? ?? ?? ?? 8b 45 e8 e8}  //weight: 1, accuracy: Low
        $x_1_2 = {64 ff 35 00 00 00 00 64 89 25 00 00 00 00 58 c3 e9 05 00 68}  //weight: 1, accuracy: Low
        $x_1_3 = {2e 63 61 62 00 00 ff ff ff ff 0a 00 00 00 ?? ?? ?? ?? ?? ?? 2e 63 61 62}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_Win32_BrobanLaw_A_2147692505_1
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/BrobanLaw.A"
        threat_id = "2147692505"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "BrobanLaw"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {3b c3 7d 05 bb 01 00 00 00 8b 45 ?? 0f b7 44 ?? ?? 8b 55 ?? 0f b7 54 ?? ?? 66 33 c2 0f b7 c0}  //weight: 1, accuracy: Low
        $x_1_2 = {3d b7 00 00 00 74 4c e8 ?? ?? ?? ?? b8 ?? ?? ?? ?? e8 ?? ?? ?? ?? 05 ?? ?? ?? ?? 50 e8 ?? ?? ?? ?? e8 ?? ?? ?? ?? 8b d0 b8 ?? ?? ?? ?? e8 ?? ?? ?? ?? 6a 24 68 ?? ?? ?? ?? 68 ?? ?? ?? ?? e8 ?? ?? ?? ?? 50 e8 ?? ?? ?? ?? 83 f8 06 75 05}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_Win32_BrobanLaw_A_2147692505_2
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/BrobanLaw.A"
        threat_id = "2147692505"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "BrobanLaw"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "11"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = "Software\\fgiusji" wide //weight: 10
        $x_1_2 = {69 00 65 00 78 00 70 00 6c 00 6f 00 72 00 65 00 2e 00 65 00 78 00 65 00 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? [0-16] 77 00 6d 00 70 00 6c 00 61 00 79 00 65 00 72 00 2e 00 65 00 78 00 65 00}  //weight: 1, accuracy: Low
        $x_1_3 = {69 00 65 00 78 00 70 00 6c 00 6f 00 72 00 65 00 2e 00 65 00 78 00 65 00 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? [0-16] 69 00 65 00 69 00 6e 00 73 00 74 00 61 00 6c 00 2e 00 65 00 78 00 65 00}  //weight: 1, accuracy: Low
        $x_1_4 = {77 00 6d 00 70 00 6c 00 61 00 79 00 65 00 72 00 2e 00 65 00 78 00 65 00 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? [0-64] 69 00 65 00 78 00 70 00 6c 00 6f 00 72 00 65 00 2e 00 65 00 78 00 65 00}  //weight: 1, accuracy: Low
        $x_1_5 = {77 00 6d 00 70 00 6c 00 61 00 79 00 65 00 72 00 2e 00 65 00 78 00 65 20 00 6f ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 5c}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_10_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule TrojanDownloader_Win32_BrobanLaw_B_2147694383_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/BrobanLaw.B"
        threat_id = "2147694383"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "BrobanLaw"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {c7 45 fc 01 00 00 00 8b 45 0c 8b 55 fc 0f b7 5c 50 fe 03 5d 10 8b c3 33 d2 52 50 8d 45 f0 e8}  //weight: 1, accuracy: High
        $x_1_2 = {64 ff 35 00 00 00 00 64 89 25 00 00 00 00 58 c3 e9 05 00 68}  //weight: 1, accuracy: Low
        $x_1_3 = {8b fe 03 f8 0f b6 17 2a 55 10 88 17 40 49 75 f0}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


rule TrojanDownloader_Win32_SmaCod_A_2147718557_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/SmaCod.A!bit"
        threat_id = "2147718557"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "SmaCod"
        severity = "Critical"
        info = "bit: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {77 77 77 2e 73 74 61 72 2d 73 6b 69 6e 2e 63 6f 6d 00 00 00 2f 62 6f 61 72 64 2f ?? ?? 2f 63 6f 64}  //weight: 2, accuracy: Low
        $x_2_2 = {75 74 69 6c [0-16] 6d 61 6c 6c 2e 63 6f 6d [0-32] 2f 62 62 73 2f 61 [0-5] 64 5f ?? ?? 2f [0-5] 63 6f 64}  //weight: 2, accuracy: Low
        $x_1_3 = {8b 55 d8 89 55 cc 83 7d cc 00 74 03 ff 55 cc}  //weight: 1, accuracy: High
        $x_1_4 = {89 45 fc 85 c0 75 08 6a ff ff 15 ?? ?? ?? ?? 8b 45 fc ff d0}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 1 of ($x_1_*))) or
            ((2 of ($x_2_*))) or
            (all of ($x*))
        )
}

rule TrojanDownloader_Win32_SmaCod_B_2147719068_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/SmaCod.B!bit"
        threat_id = "2147719068"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "SmaCod"
        severity = "Critical"
        info = "bit: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {77 77 77 2e 73 74 61 72 2d 73 6b 69 6e 2e 63 6f 6d 00 00 00 2f 62 6f 61 72 64 2f ?? ?? 2f 63 6f 64}  //weight: 2, accuracy: Low
        $x_2_2 = {75 74 69 6c [0-16] 6d 61 6c 6c 2e 63 6f 6d [0-32] 2f 62 62 73 2f 61 [0-5] 64 5f ?? ?? 2f [0-5] 63 6f 64}  //weight: 2, accuracy: Low
        $x_1_3 = {83 7d fc 00 74 ?? ff 55 ?? 6a 00 ff 15}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 1 of ($x_1_*))) or
            ((2 of ($x_2_*))) or
            (all of ($x*))
        )
}

rule TrojanDownloader_Win32_SmaCod_C_2147719069_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/SmaCod.C!bit"
        threat_id = "2147719069"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "SmaCod"
        severity = "Critical"
        info = "bit: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "11"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {51 6a 00 ff 15 ?? ?? ?? ?? 89 45 ?? 8d 55 ?? 52 8b 45 ?? 2b 45 ?? 50 8b 4d ?? 03 4d ?? 51 8b 55 ?? 52 ff 15}  //weight: 5, accuracy: Low
        $x_5_2 = "/cod" ascii //weight: 5
        $x_1_3 = {8b 55 d8 89 55 cc 83 7d cc 00 74 03 ff 55 cc}  //weight: 1, accuracy: High
        $x_1_4 = {89 45 fc 85 c0 75 08 6a ff ff 15 ?? ?? ?? ?? 8b 45 fc ff d0}  //weight: 1, accuracy: Low
        $x_1_5 = {83 7d fc 00 74 ?? ff 55 ?? 6a 00 ff 15}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_5_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}


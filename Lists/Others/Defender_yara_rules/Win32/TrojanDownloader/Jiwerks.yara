rule TrojanDownloader_Win32_Jiwerks_A_2147649756_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Jiwerks.A"
        threat_id = "2147649756"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Jiwerks"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "SKYPE,GOOGLETALK,NOTEPAD,WMPLAYER,NET,SPAWNED,MYAPP,|!|HAL9TH|!|" wide //weight: 1
        $x_1_2 = {3a 2f 2f 61 64 2e [0-32] 2e 69 6e 66 6f 3a 38 30 38 30 2f 75 70 64 61 74 65}  //weight: 1, accuracy: Low
        $x_1_3 = "DllMian" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_Win32_Jiwerks_B_2147654617_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Jiwerks.B"
        threat_id = "2147654617"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Jiwerks"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {3a 2f 2f 61 64 [0-1] 2e 37 65 72 39 77 33 6b 69 6a 73 34 2e 69 6e 66 6f 3a 38 30 38 30 2f 00 [0-3] 31 32 33 34 35 36 00 00 ff ff ff ff ?? 00 00 00 [0-60] 2e 65 78 65 00}  //weight: 1, accuracy: Low
        $x_1_2 = {3a 2f 2f 61 30 31 2e 6a 61 63 6b 70 6f 73 65 67 6f 6f 64 2e 69 6e 66 6f 3a 38 30 38 30 2f 00 [0-3] 31 32 33 34 35 36 00 00 ff ff ff ff ?? 00 00 00 [0-60] 2e 65 78 65 00}  //weight: 1, accuracy: Low
        $x_1_3 = {3a 2f 2f 36 34 2e 31 32 30 2e 31 38 39 2e 37 30 3a 38 30 38 30 2f 00 00 31 32 33 34 35 36 00 00 ff ff ff ff ?? 00 00 00 [0-60] 2e 65 78 65 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule TrojanDownloader_Win32_Jiwerks_C_2147658598_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Jiwerks.C"
        threat_id = "2147658598"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Jiwerks"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "151"
        strings_accuracy = "Low"
    strings:
        $x_100_1 = {c7 80 9c 00 00 00 30 75 00 00 8b 45 e8 8a 80 11 01 00 00 0a 05 ?? ?? 43 00 8b 55 e8 88 82 11 01 00 00 8b 45 e8 c6 80 04 01 00 00 01}  //weight: 100, accuracy: Low
        $x_50_2 = "rinima.hypk38.com:8080/" ascii //weight: 50
        $x_50_3 = "8.szhdsj.com:8080/" ascii //weight: 50
        $x_50_4 = "bk.datooo.com:8080/" ascii //weight: 50
        $x_50_5 = "bc.ki59eng0hsames.info:8080/" ascii //weight: 50
        $x_50_6 = "ck222.caiji168.com:8080/" ascii //weight: 50
        $x_1_7 = {61 3d 6f 26 76 3d 00 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((3 of ($x_50_*) and 1 of ($x_1_*))) or
            ((4 of ($x_50_*))) or
            ((1 of ($x_100_*) and 1 of ($x_50_*) and 1 of ($x_1_*))) or
            ((1 of ($x_100_*) and 2 of ($x_50_*))) or
            (all of ($x*))
        )
}


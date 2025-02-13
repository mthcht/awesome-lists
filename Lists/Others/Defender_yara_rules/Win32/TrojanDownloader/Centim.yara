rule TrojanDownloader_Win32_Centim_2147574189_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Centim"
        threat_id = "2147574189"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Centim"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "25"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "daily-weather" ascii //weight: 1
        $x_1_2 = "GET %s HTTP/1" ascii //weight: 1
        $x_1_3 = "ProgramFilesDir" ascii //weight: 1
        $x_1_4 = "ShellExecute" ascii //weight: 1
        $x_20_5 = {55 89 e5 83 ec 08 83 c4 f4 6a 02 a1 ?? ?? ?? ?? ff d0 e8 69 ff ff ff 89 ec 5d c3}  //weight: 20, accuracy: Low
        $x_2_6 = {7c 77 77 77 [0-20] 2e [0-3] 7c 2f [0-20] 7c [0-32] 7c [0-16] 2e 65 78 65 7c}  //weight: 2, accuracy: Low
        $x_4_7 = {7c 61 75 74 6f 2e [0-20] 2e [0-3] 7c 2f [0-26] 7c [0-26] 7c 77 65 61 74 68 65 72 2e 65 78 65 7c}  //weight: 4, accuracy: Low
        $x_4_8 = {7c 74 69 6d 65 [0-20] 2e [0-3] 7c 2f [0-26] 7c [0-26] 7c 74 69 6d 65 2e 65 78 65 7c}  //weight: 4, accuracy: Low
        $x_4_9 = {7c 61 72 63 68 69 76 65 2e [0-20] 2e [0-3] 7c 2f [0-26] 7c [0-26] 7c 61 72 63 68 69 76 65 2e 65 78 65 7c}  //weight: 4, accuracy: Low
        $x_2_10 = {83 c4 f4 83 c4 f4 6a 00 e8 ?? ?? ?? ?? 50 e8 ?? ?? ?? ?? 83 c4 20 83 c4 f8 68 00 04 00 00 8d ?? ?? ?? ?? ?? 50 e8 [0-21] 83 c4 fc 68 b8 0b 00 00}  //weight: 2, accuracy: Low
        $x_3_11 = {83 c4 fc 68 ?? ?? 00 00 6a 00 50 e8 ?? ?? ?? ?? 83 c4 10 [0-3] 83 c4 f8 68 ?? ?? ?? ?? 8d 85 ?? ?? ?? ?? 50 e8}  //weight: 3, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_20_*) and 1 of ($x_2_*) and 3 of ($x_1_*))) or
            ((1 of ($x_20_*) and 2 of ($x_2_*) and 1 of ($x_1_*))) or
            ((1 of ($x_20_*) and 1 of ($x_3_*) and 2 of ($x_1_*))) or
            ((1 of ($x_20_*) and 1 of ($x_3_*) and 1 of ($x_2_*))) or
            ((1 of ($x_20_*) and 1 of ($x_4_*) and 1 of ($x_1_*))) or
            ((1 of ($x_20_*) and 1 of ($x_4_*) and 1 of ($x_2_*))) or
            ((1 of ($x_20_*) and 1 of ($x_4_*) and 1 of ($x_3_*))) or
            ((1 of ($x_20_*) and 2 of ($x_4_*))) or
            (all of ($x*))
        )
}


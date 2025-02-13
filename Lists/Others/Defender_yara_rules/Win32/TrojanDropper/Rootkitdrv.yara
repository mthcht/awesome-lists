rule TrojanDropper_Win32_Rootkitdrv_AG_2147593790_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:Win32/Rootkitdrv.AG"
        threat_id = "2147593790"
        type = "TrojanDropper"
        platform = "Win32: Windows 32-bit platform"
        family = "Rootkitdrv"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b 45 08 03 47 14 8b ce 03 4f 0c 81 3f 2e 64 61 74}  //weight: 1, accuracy: High
        $x_1_2 = {8d b3 f8 00 00 00 8b 45 08 03 46 14 8b cf 03 4e 0c 81 3e 2e 64 61 74}  //weight: 1, accuracy: High
        $x_4_3 = {8b 5d 08 8b 45 0c 8a 0f 80 f9 00 74 09 30 0b 48}  //weight: 4, accuracy: High
        $x_2_4 = {64 a1 18 00 00 00 8b 40 30 8b 1d ?? ?? ?? ?? 89 58 08}  //weight: 2, accuracy: Low
        $x_2_5 = {83 c6 03 56 ff 15}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_4_*) and 1 of ($x_2_*) and 1 of ($x_1_*))) or
            ((1 of ($x_4_*) and 2 of ($x_2_*))) or
            (all of ($x*))
        )
}


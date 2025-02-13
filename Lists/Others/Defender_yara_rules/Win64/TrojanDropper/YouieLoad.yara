rule TrojanDropper_Win64_YouieLoad_A_2147911418_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:Win64/YouieLoad.A!dha"
        threat_id = "2147911418"
        type = "TrojanDropper"
        platform = "Win64: Windows 64-bit platform"
        family = "YouieLoad"
        severity = "Critical"
        info = "dha: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "150"
        strings_accuracy = "Low"
    strings:
        $x_100_1 = {50 45 00 00 ?? 8d 2c ?? 75 ?? b8 64 86 00 00 66 39 45 04 75}  //weight: 100, accuracy: Low
        $x_50_2 = {42 8b 44 1b fc 49 83 c3 10 41 33 44 2b ec 41 89 43 ec 42 8b 44 1b f0 41 33 44 2b f0}  //weight: 50, accuracy: High
        $x_50_3 = {8b 4c 03 fc 48 8d 40 10 33 4c 28 ec 89 48 ec 8b 4c 03 f0 33 4c 28 f0}  //weight: 50, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_100_*) and 1 of ($x_50_*))) or
            (all of ($x*))
        )
}


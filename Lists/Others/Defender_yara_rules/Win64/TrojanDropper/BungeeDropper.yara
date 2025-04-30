rule TrojanDropper_Win64_BungeeDropper_A_2147940353_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:Win64/BungeeDropper.A!dha"
        threat_id = "2147940353"
        type = "TrojanDropper"
        platform = "Win64: Windows 64-bit platform"
        family = "BungeeDropper"
        severity = "Critical"
        info = "dha: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {48 89 44 24 ?? 48 8b 44 24 ?? 48 05 fc 03 00 00 48 89 44 24 ?? 48 8b 44 24 ?? 48 05 f8 03 00 00 48 89 44 24 ?? 48 8b 44 24 ?? 8b 00 89 44 24 ?? 48 8b 44 24}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


rule Backdoor_Win64_RoundWorm_A_2147922206_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win64/RoundWorm.A!dha"
        threat_id = "2147922206"
        type = "Backdoor"
        platform = "Win64: Windows 64-bit platform"
        family = "RoundWorm"
        severity = "Critical"
        info = "dha: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {83 c5 03 48 63 cd 48 8b 46 ?? 48 3b c8 0f 82 ?? ?? ?? ?? 48 8b 56 ?? 48 83 fa 0f 76 2c 48 ff c2 48 8b 0e 48 81 fa 00 10 00 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


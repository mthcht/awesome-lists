rule TrojanDropper_Win32_CrashDat_A_2147967370_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:Win32/CrashDat.A!dha"
        threat_id = "2147967370"
        type = "TrojanDropper"
        platform = "Win32: Windows 32-bit platform"
        family = "CrashDat"
        severity = "Critical"
        info = "dha: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {16 01 15 53 09 16 56 19 43 03 0d 06 1d}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


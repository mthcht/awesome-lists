rule Backdoor_Win64_Tickler_A_2147919673_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win64/Tickler.A!dha"
        threat_id = "2147919673"
        type = "Backdoor"
        platform = "Win64: Windows 64-bit platform"
        family = "Tickler"
        severity = "Critical"
        info = "dha: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {e9 71 0b 00 00 c6 84 24 ?? ?? ?? ?? ?? b0 ?? b1 ?? b2 ?? 41 b0 ?? 41 b1 ?? 41 b2 ?? 45 33 db 34 ?? 88 84 24}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


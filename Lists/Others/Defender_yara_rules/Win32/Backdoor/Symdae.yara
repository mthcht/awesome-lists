rule Backdoor_Win32_Symdae_A_2147650814_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Symdae.A"
        threat_id = "2147650814"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Symdae"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b 7c 24 10 8b d7 2b cf 8a 04 11 8a 1a 32 d8 88 1a 42 4e 75 f3 8b c7}  //weight: 1, accuracy: High
        $x_1_2 = {68 a0 bb 0d 00 ff 15 ?? ?? ?? ?? b8 6e 3a 00 10 c3 33 db 89 5d fc}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


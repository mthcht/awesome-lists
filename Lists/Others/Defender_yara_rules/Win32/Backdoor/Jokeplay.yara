rule Backdoor_Win32_Jokeplay_A_2147600943_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Jokeplay.A"
        threat_id = "2147600943"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Jokeplay"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "9"
        strings_accuracy = "High"
    strings:
        $x_6_1 = "\\Joke-1\\prjJoke.vbp" wide //weight: 6
        $x_3_2 = "http://media.ebaumsworld.com/aicha.swf" wide //weight: 3
        $x_2_3 = "C:\\gu.wav" wide //weight: 2
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_6_*) and 1 of ($x_3_*))) or
            (all of ($x*))
        )
}


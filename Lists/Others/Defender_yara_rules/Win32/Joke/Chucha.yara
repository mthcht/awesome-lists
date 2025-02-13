rule Joke_Win32_Chucha_A_2147600330_0
{
    meta:
        author = "defender2yara"
        detection_name = "Joke:Win32/Chucha.A"
        threat_id = "2147600330"
        type = "Joke"
        platform = "Win32: Windows 32-bit platform"
        family = "Chucha"
        severity = "Mid"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {43 48 55 43 48 41 00 00 55 8b ec 33 c0 55 68 ?? ?? 44 00 64 ff 30 64 89 20 ff 05 ?? ?? 44 00 75 2a b8 ?? ?? 44 00 b9 05 00 00 00 8b 15 ?? ?? 40 00 e8 ?? ?? ?? ?? b8 ?? ?? 44 00 b9 05 00 00 00 8b 15 ?? ?? 40 00 e8 ?? ?? ?? ?? 33 c0 5a 59 59 64 89 10 68 ?? ?? 44 00 c3}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


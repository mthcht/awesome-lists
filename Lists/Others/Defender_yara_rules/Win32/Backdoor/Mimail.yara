rule Backdoor_Win32_Mimail_A_2147647702_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Mimail.A"
        threat_id = "2147647702"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Mimail"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_3_1 = {52 6a 00 6a 00 6a 16 8b 85 ?? ?? ff ff 50 ff 15 ?? ?? ?? ?? 89 85 24 ?? ?? ?? 83 bd 24 02 00 75 ?? 83 bd 24 02 00 0f 85 d5 05 00 00 ff 15 ?? ?? ?? ?? 83 f8 7a 0f 85}  //weight: 3, accuracy: Low
        $x_1_2 = "Opera/9.80 (Windows NT 6.1; U; ru) Presto/2.7.62 Version/11.01" wide //weight: 1
        $x_1_3 = "WinHttpClient" wide //weight: 1
        $x_1_4 = {47 00 45 00 54 00 00 00 47 00 45 00 54 00 00 00 50 00 4f 00 53 00 54 00 00 00 00 00 50 00 4f 00 53 00 54 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_3_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}


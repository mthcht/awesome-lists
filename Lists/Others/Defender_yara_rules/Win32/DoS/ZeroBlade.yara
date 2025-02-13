rule DoS_Win32_ZeroBlade_A_2147839784_0
{
    meta:
        author = "defender2yara"
        detection_name = "DoS:Win32/ZeroBlade.A!dha"
        threat_id = "2147839784"
        type = "DoS"
        platform = "Win32: Windows 32-bit platform"
        family = "ZeroBlade"
        severity = "Critical"
        info = "dha: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "200"
        strings_accuracy = "Low"
    strings:
        $x_100_1 = {b9 69 00 00 00 66 89 ?? ?? ?? ba 73 00 00 00 66 89 ?? ?? ?? b9 61 00 00 00}  //weight: 100, accuracy: Low
        $x_100_2 = {8b 7c 24 2c c1 e7 0a 57 6a 40 ff}  //weight: 100, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


rule PWS_Win32_Fifesock_A_2147644584_0
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:Win32/Fifesock.gen!A"
        threat_id = "2147644584"
        type = "PWS"
        platform = "Win32: Windows 32-bit platform"
        family = "Fifesock"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {6e 73 70 72 c7 45 ?? 34 2e 64 6c 66 c7 45 ?? 6c 00 c7 45 ?? 77 73 32 5f c7 45 ?? 33 32 2e 64 66 c7 45 ?? 6c 6c c6 45 ?? 00 c7 45 ?? 77 69 6e 69}  //weight: 1, accuracy: Low
        $x_1_2 = {6a 40 68 00 30 00 00 ?? ?? 05 ?? 6a 00 ff 15 [0-12] 51 50 89 86 ?? 00 00 00 e8 ?? ?? ?? ?? 8b ?? ?? 00 00 00 [0-3] c6 ?? ?? e9}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


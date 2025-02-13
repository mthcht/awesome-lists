rule Ransom_Win32_Winshulock_A_2147693143_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/Winshulock.A"
        threat_id = "2147693143"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "Winshulock"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {c7 04 01 01 01 01 01 83 c1 04 3b 4d ?? 72 f1 59 58 ba 02 00 00 00 8b 45 ?? e8 ?? ?? ?? ?? 8b d8 83 fb ff 74 2f}  //weight: 2, accuracy: Low
        $x_2_2 = "shutdown -s -t 00 -c error > nul" ascii //weight: 2
        $x_1_3 = {5c 5c 2e 5c 50 68 79 73 69 63 61 6c 44 72 69 76 65 36 [0-12] 5c 5c 2e 5c 50 68 79 73 69 63 61 6c 44 72 69 76 65 37}  //weight: 1, accuracy: Low
        $x_1_4 = "WinUpdate" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_2_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}


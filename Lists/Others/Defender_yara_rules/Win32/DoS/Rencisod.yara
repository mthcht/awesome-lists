rule DoS_Win32_Rencisod_A_2147828606_0
{
    meta:
        author = "defender2yara"
        detection_name = "DoS:Win32/Rencisod.A"
        threat_id = "2147828606"
        type = "DoS"
        platform = "Win32: Windows 32-bit platform"
        family = "Rencisod"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "31"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {2e 00 70 00 64 00 66 00 [0-4] 2e 00 64 00 6f 00 63 00 [0-4] 2e 00 64 00 6f 00 63 00 78 00}  //weight: 10, accuracy: Low
        $x_10_2 = {2e 70 64 66 [0-4] 2e 64 6f 63 [0-4] 2e 64 6f 63 78}  //weight: 10, accuracy: Low
        $x_10_3 = {2e 00 73 00 71 00 6c 00 [0-4] 2e 00 6d 00 73 00 67 00 [0-4] 2e 00 70 00 73 00 74 00}  //weight: 10, accuracy: Low
        $x_10_4 = {2e 73 71 6c [0-4] 2e 6d 73 67 [0-4] 2e 70 73 74}  //weight: 10, accuracy: Low
        $x_1_5 = "We have {0} to upload and {1} completed" ascii //weight: 1
        $x_1_6 = "-C \"Stop-Process -Id {0}; Start-Sleep 3; Set-Content -Path '{1}' -Value 0\"" ascii //weight: 1
        $x_5_7 = "sync_enc" ascii //weight: 5
        $x_5_8 = {68 00 74 00 74 00 70 00 3a 00 2f 00 2f 00 [0-5] 2f 00 64 00 61 00 74 00 61 00 2f 00}  //weight: 5, accuracy: Low
        $x_5_9 = {68 74 74 70 3a 2f 2f [0-5] 2f 64 61 74 61 2f}  //weight: 5, accuracy: Low
        $x_5_10 = "B01BF3F2A3BE120B105358BB1AB8C510A443C379DA126BBE4DB94A7BF097262E" ascii //weight: 5
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_10_*) and 4 of ($x_5_*) and 1 of ($x_1_*))) or
            ((2 of ($x_10_*) and 2 of ($x_5_*) and 1 of ($x_1_*))) or
            ((2 of ($x_10_*) and 3 of ($x_5_*))) or
            ((3 of ($x_10_*) and 1 of ($x_1_*))) or
            ((3 of ($x_10_*) and 1 of ($x_5_*))) or
            ((4 of ($x_10_*))) or
            (all of ($x*))
        )
}


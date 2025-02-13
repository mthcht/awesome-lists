rule TrojanProxy_Win32_Prorat_A_2147575542_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanProxy:Win32/Prorat.gen!A"
        threat_id = "2147575542"
        type = "TrojanProxy"
        platform = "Win32: Windows 32-bit platform"
        family = "Prorat"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "atm_dURL=http://" ascii //weight: 1
        $x_1_2 = "00-d7bf-11d1-9947-00c0Cf98bbc9}" ascii //weight: 1
        $x_1_3 = "\\ffservice.e" ascii //weight: 1
        $x_1_4 = "\\d_service.e" ascii //weight: 1
        $x_2_5 = {80 3c 28 20 74 1b 43 56 4d ff d7 3b d8 7c ee 56 c6 46 08 5c e8}  //weight: 2, accuracy: High
        $x_3_6 = {74 34 6a 00 8d 84 24 [0-0] 6a 00 8d 8c 24 2c 04 00 00 50 51 6a 00 e8 ?? ?? 00 00 85 c0 75 15 6a 05 50 8d 94 24 94 05 00 00 50 52 50 50 ff}  //weight: 3, accuracy: Low
        $x_2_7 = {83 c4 24 a1 8c 10 40 00 8b 30 89 75 8c 80 3e 22 75 3a 46 89 75 8c 8a 06 3a c3 74 04 3c 22 75 f2 80 3e 22 75 04 46 89 75 8c 8a 06 3a c3 74 04 3c 20 76 f2 89 5d d0 8d 45 a4}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 3 of ($x_1_*))) or
            ((2 of ($x_2_*) and 1 of ($x_1_*))) or
            ((1 of ($x_3_*) and 2 of ($x_1_*))) or
            ((1 of ($x_3_*) and 1 of ($x_2_*))) or
            (all of ($x*))
        )
}


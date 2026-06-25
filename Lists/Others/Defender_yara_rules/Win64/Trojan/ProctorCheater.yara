rule Trojan_Win64_ProctorCheater_A_2147972238_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/ProctorCheater.A"
        threat_id = "2147972238"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "ProctorCheater"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "13"
        strings_accuracy = "High"
    strings:
        $x_5_1 = "//evadus.net/app_login.html?port=" ascii //weight: 5
        $x_5_2 = "//evadus.net/rooms.html?room=" ascii //weight: 5
        $x_2_3 = "evadus_" ascii //weight: 2
        $x_3_4 = "/IMWJin638BQ" ascii //weight: 3
        $x_3_5 = "/otimfkMFESg" ascii //weight: 3
        $x_3_6 = "/gHlafN620_g" ascii //weight: 3
        $x_2_7 = "RDP Wrapper" ascii //weight: 2
        $x_2_8 = "//github.com/asmtron/rdpwrap" ascii //weight: 2
        $x_1_9 = "psi.png" ascii //weight: 1
        $x_1_10 = "inspera.png" ascii //weight: 1
        $x_1_11 = "respondus.png" ascii //weight: 1
        $x_1_12 = "pearsonvue.png" ascii //weight: 1
        $x_1_13 = "ProProctor" ascii //weight: 1
        $x_1_14 = "Safe Exam Browser" ascii //weight: 1
        $x_1_15 = "LockDownBrowser.exe" ascii //weight: 1
        $x_1_16 = "AIModelSection" ascii //weight: 1
        $x_1_17 = "Anthropic" ascii //weight: 1
        $x_1_18 = "deepseek-v" ascii //weight: 1
        $x_1_19 = "gemini-" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 11 of ($x_1_*))) or
            ((2 of ($x_2_*) and 9 of ($x_1_*))) or
            ((3 of ($x_2_*) and 7 of ($x_1_*))) or
            ((1 of ($x_3_*) and 10 of ($x_1_*))) or
            ((1 of ($x_3_*) and 1 of ($x_2_*) and 8 of ($x_1_*))) or
            ((1 of ($x_3_*) and 2 of ($x_2_*) and 6 of ($x_1_*))) or
            ((1 of ($x_3_*) and 3 of ($x_2_*) and 4 of ($x_1_*))) or
            ((2 of ($x_3_*) and 7 of ($x_1_*))) or
            ((2 of ($x_3_*) and 1 of ($x_2_*) and 5 of ($x_1_*))) or
            ((2 of ($x_3_*) and 2 of ($x_2_*) and 3 of ($x_1_*))) or
            ((2 of ($x_3_*) and 3 of ($x_2_*) and 1 of ($x_1_*))) or
            ((3 of ($x_3_*) and 4 of ($x_1_*))) or
            ((3 of ($x_3_*) and 1 of ($x_2_*) and 2 of ($x_1_*))) or
            ((3 of ($x_3_*) and 2 of ($x_2_*))) or
            ((1 of ($x_5_*) and 8 of ($x_1_*))) or
            ((1 of ($x_5_*) and 1 of ($x_2_*) and 6 of ($x_1_*))) or
            ((1 of ($x_5_*) and 2 of ($x_2_*) and 4 of ($x_1_*))) or
            ((1 of ($x_5_*) and 3 of ($x_2_*) and 2 of ($x_1_*))) or
            ((1 of ($x_5_*) and 1 of ($x_3_*) and 5 of ($x_1_*))) or
            ((1 of ($x_5_*) and 1 of ($x_3_*) and 1 of ($x_2_*) and 3 of ($x_1_*))) or
            ((1 of ($x_5_*) and 1 of ($x_3_*) and 2 of ($x_2_*) and 1 of ($x_1_*))) or
            ((1 of ($x_5_*) and 1 of ($x_3_*) and 3 of ($x_2_*))) or
            ((1 of ($x_5_*) and 2 of ($x_3_*) and 2 of ($x_1_*))) or
            ((1 of ($x_5_*) and 2 of ($x_3_*) and 1 of ($x_2_*))) or
            ((1 of ($x_5_*) and 3 of ($x_3_*))) or
            ((2 of ($x_5_*) and 3 of ($x_1_*))) or
            ((2 of ($x_5_*) and 1 of ($x_2_*) and 1 of ($x_1_*))) or
            ((2 of ($x_5_*) and 2 of ($x_2_*))) or
            ((2 of ($x_5_*) and 1 of ($x_3_*))) or
            (all of ($x*))
        )
}


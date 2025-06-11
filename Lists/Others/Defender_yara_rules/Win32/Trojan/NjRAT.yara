rule Trojan_Win32_NjRAT_A_2147917666_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/NjRAT.A!MTB"
        threat_id = "2147917666"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "NjRAT"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_4_1 = {f5 00 00 00 00 f5 80 00 00 00 6c 0c 00 4d 50 ff 08 40 04 ?? ff 0a 00 00 10 00 04 ?? ff fc 60 3c}  //weight: 4, accuracy: Low
        $x_2_2 = {f5 00 00 00 00 f5 ff ff ff ff f5 01 00 00 00 f5 00 00 00 00 1b 04 00 80 0c}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_NjRAT_NK_2147921844_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/NjRAT.NK!MTB"
        threat_id = "2147921844"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "NjRAT"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_AUTOITHSTR_EXT"
        threshold = "7"
        strings_accuracy = "Low"
    strings:
        $x_3_1 = {46 00 49 00 4c 00 45 00 49 00 4e 00 53 00 54 00 41 00 4c 00 4c 00 20 00 28 00 20 00 22 00 [0-47] 2e 00 65 00 78 00 65 00 22 00 20 00 2c 00 20 00 24 00 50 00 54 00 20 00 26 00 20 00 22 00 2f 00 00 2e 00 65 00 78 00 65 00 22 00 20 00 29 00}  //weight: 3, accuracy: Low
        $x_3_2 = {46 49 4c 45 49 4e 53 54 41 4c 4c 20 28 20 22 [0-47] 2e 65 78 65 22 20 2c 20 24 50 54 20 26 20 22 2f 00 2e 65 78 65 22 20 29}  //weight: 3, accuracy: Low
        $x_1_3 = {52 00 55 00 4e 00 20 00 28 00 20 00 24 00 50 00 54 00 20 00 26 00 20 00 22 00 2f 00 [0-47] 2e 00 65 00 78 00 65 00 22 00 20 00 29 00}  //weight: 1, accuracy: Low
        $x_1_4 = {52 55 4e 20 28 20 24 50 54 20 26 20 22 2f [0-47] 2e 65 78 65 22 20 29}  //weight: 1, accuracy: Low
        $x_1_5 = "$PT = @TEMPDIR" ascii //weight: 1
        $x_1_6 = {46 00 49 00 4c 00 45 00 49 00 4e 00 53 00 54 00 41 00 4c 00 4c 00 20 00 28 00 20 00 22 00 [0-47] 2e 00 70 00 68 00 70 00 22 00 20 00 2c 00 20 00 24 00 50 00 54 00 20 00 26 00 20 00 22 00 2f 00 00 2e 00 70 00 68 00 70 00 22 00 20 00 29 00}  //weight: 1, accuracy: Low
        $x_1_7 = {46 49 4c 45 49 4e 53 54 41 4c 4c 20 28 20 22 [0-47] 2e 70 68 70 22 20 2c 20 24 50 54 20 26 20 22 2f 00 2e 70 68 70 22 20 29}  //weight: 1, accuracy: Low
        $x_1_8 = {53 00 48 00 45 00 4c 00 4c 00 45 00 58 00 45 00 43 00 55 00 54 00 45 00 20 00 28 00 20 00 22 00 [0-47] 2e 00 70 00 68 00 70 00 22 00 20 00 2c 00 20 00 22 00 22 00 20 00 2c 00 20 00 24 00 50 00 54 00 20 00 2c 00 20 00 22 00 6f 00 70 00 65 00 6e 00 22 00 20 00 29 00}  //weight: 1, accuracy: Low
        $x_1_9 = {53 48 45 4c 4c 45 58 45 43 55 54 45 20 28 20 22 [0-47] 2e 70 68 70 22 20 2c 20 22 22 20 2c 20 24 50 54 20 2c 20 22 6f 70 65 6e 22 20 29}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((7 of ($x_1_*))) or
            ((1 of ($x_3_*) and 4 of ($x_1_*))) or
            ((2 of ($x_3_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_NjRAT_SAC_2147943377_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/NjRAT.SAC!MTB"
        threat_id = "2147943377"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "NjRAT"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {22 00 43 00 3a 00 5c 00 57 00 49 00 4e 00 44 00 4f 00 57 00 53 00 5c 00 53 00 59 00 53 00 54 00 45 00 4d 00 33 00 32 00 5c 00 63 00 6d 00 64 00 22 00 20 00 2f 00 63 00 20 00 43 00 3a 00 5c 00 54 00 45 00 4d 00 50 00 5c 00 [0-20] 2e 00 62 00 61 00 74 00 20 00 43 00 3a 00 5c 00 [0-20] 2e 00 65 00 78 00 65 00}  //weight: 2, accuracy: Low
        $x_1_2 = "powershell -Command \"(New-Object System.Net.WebClient).DownloadFile('%url1%', '%output1%')\"" ascii //weight: 1
        $x_1_3 = {74 00 6d 00 70 00 5c 00 [0-20] 2e 00 74 00 6d 00 70 00 5c 00 [0-20] 2e 00 74 00 6d 00 70 00}  //weight: 1, accuracy: Low
        $x_1_4 = "Debugger breakpoint reached" wide //weight: 1
        $x_1_5 = "start \"\" \"%output1%\"" wide //weight: 1
        $x_1_6 = "b2eincfilepath" wide //weight: 1
        $x_1_7 = {54 00 45 00 4d 00 50 00 5c 00 [0-20] 2e 00 74 00 6d 00 70 00 5c 00 [0-20] 2e 00 74 00 6d 00 70 00 5c 00 65 00 78 00 74 00 64 00 2e 00 65 00 78 00 65 00}  //weight: 1, accuracy: Low
        $x_1_8 = {54 45 4d 50 5c [0-20] 2e 74 6d 70 5c [0-20] 2e 74 6d 70 5c 65 78 74 64 2e 65 78 65}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 6 of ($x_1_*))) or
            (all of ($x*))
        )
}


rule Trojan_Win32_Horst_B_2147600697_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Horst.gen!B"
        threat_id = "2147600697"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Horst"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "16"
        strings_accuracy = "High"
    strings:
        $x_10_1 = {6e 65 77 73 2e 6d 65 64 62 6f 64 2e 63 6f 6d 00}  //weight: 10, accuracy: High
        $x_5_2 = {61 64 73 2e 7a 61 62 6c 65 6e 2e 63 6f 6d 00}  //weight: 5, accuracy: High
        $x_5_3 = {48 6f 74 6d 61 69 6c 4d 61 69 6c 65 72 2e 70 64 62 00}  //weight: 5, accuracy: High
        $x_5_4 = {48 6f 74 6d 61 69 6c 52 65 67 69 73 74 72 61 72 2e 70 64 62 00}  //weight: 5, accuracy: High
        $x_5_5 = {48 6f 74 6d 61 69 6c 52 65 67 69 73 74 72 61 72 4d 61 69 6c 65 72 2e 70 64 62 00}  //weight: 5, accuracy: High
        $x_5_6 = {48 6f 74 6d 61 69 6c 52 65 67 69 73 74 72 61 72 41 6e 6f 74 68 65 72 2e 70 64 62 00}  //weight: 5, accuracy: High
        $x_5_7 = {59 61 68 6f 6f 4d 61 69 6c 65 72 2e 70 64 62 00}  //weight: 5, accuracy: High
        $x_5_8 = {41 4f 4c 52 65 67 65 72 2e 70 64 62 00}  //weight: 5, accuracy: High
        $x_5_9 = {41 4f 4c 4d 61 69 6c 65 72 2e 70 64 62 00}  //weight: 5, accuracy: High
        $x_5_10 = {47 6d 61 69 6c 4d 61 69 6c 65 72 2e 70 64 62 00}  //weight: 5, accuracy: High
        $x_5_11 = {47 6d 61 69 6c 52 65 67 69 73 74 72 61 72 2e 70 64 62 00}  //weight: 5, accuracy: High
        $x_5_12 = {47 6d 61 69 6c 52 65 67 69 73 74 72 61 72 4d 61 69 6c 65 72 2e 70 64 62 00}  //weight: 5, accuracy: High
        $x_3_13 = {57 61 72 6e 6f 6e 42 61 64 43 65 72 74 52 65 63 76 69 6e 67 00}  //weight: 3, accuracy: High
        $x_2_14 = {69 6e 6e 65 72 5f 78 6d 6c 00 00 00 74 61 67 5f 6e 61 6d 65}  //weight: 2, accuracy: High
        $x_2_15 = {3c 2f 53 55 42 4a 3e 00}  //weight: 2, accuracy: High
        $x_2_16 = {7b 25 4c 49 4e 4b 7d 00}  //weight: 2, accuracy: High
        $x_2_17 = {52 65 61 63 74 69 76 61 74 65 41 63 6f 75 6e 74 20 65 72 72 6f 72 00}  //weight: 2, accuracy: High
        $x_2_18 = {4d 65 73 73 61 67 65 20 53 65 6e 74 00}  //weight: 2, accuracy: High
        $x_2_19 = "GetCaptchaStringFromResponse" ascii //weight: 2
        $x_2_20 = "GetCaptchaString" ascii //weight: 2
        $x_2_21 = "GetCaptchaCode" ascii //weight: 2
        $x_2_22 = "SetCaptchaCodeAndSubmit" ascii //weight: 2
        $x_2_23 = {43 61 6e 27 74 20 61 73 6b 20 70 69 63 74 75 72 65 00}  //weight: 2, accuracy: High
        $x_2_24 = "All Sent." ascii //weight: 2
        $x_2_25 = {71 75 65 73 74 61 6e 73 77 65 72 00}  //weight: 2, accuracy: High
        $x_2_26 = {43 52 65 67 69 73 74 72 61 72 56 69 65 77 00}  //weight: 2, accuracy: High
        $x_1_27 = {6d 61 69 6c 73 00}  //weight: 1, accuracy: High
        $x_1_28 = {61 63 63 6f 75 6e 74 73 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((7 of ($x_2_*) and 2 of ($x_1_*))) or
            ((8 of ($x_2_*))) or
            ((1 of ($x_3_*) and 6 of ($x_2_*) and 1 of ($x_1_*))) or
            ((1 of ($x_3_*) and 7 of ($x_2_*))) or
            ((1 of ($x_5_*) and 5 of ($x_2_*) and 1 of ($x_1_*))) or
            ((1 of ($x_5_*) and 6 of ($x_2_*))) or
            ((1 of ($x_5_*) and 1 of ($x_3_*) and 3 of ($x_2_*) and 2 of ($x_1_*))) or
            ((1 of ($x_5_*) and 1 of ($x_3_*) and 4 of ($x_2_*))) or
            ((2 of ($x_5_*) and 2 of ($x_2_*) and 2 of ($x_1_*))) or
            ((2 of ($x_5_*) and 3 of ($x_2_*))) or
            ((2 of ($x_5_*) and 1 of ($x_3_*) and 1 of ($x_2_*) and 1 of ($x_1_*))) or
            ((2 of ($x_5_*) and 1 of ($x_3_*) and 2 of ($x_2_*))) or
            ((3 of ($x_5_*) and 1 of ($x_1_*))) or
            ((3 of ($x_5_*) and 1 of ($x_2_*))) or
            ((3 of ($x_5_*) and 1 of ($x_3_*))) or
            ((4 of ($x_5_*))) or
            ((1 of ($x_10_*) and 2 of ($x_2_*) and 2 of ($x_1_*))) or
            ((1 of ($x_10_*) and 3 of ($x_2_*))) or
            ((1 of ($x_10_*) and 1 of ($x_3_*) and 1 of ($x_2_*) and 1 of ($x_1_*))) or
            ((1 of ($x_10_*) and 1 of ($x_3_*) and 2 of ($x_2_*))) or
            ((1 of ($x_10_*) and 1 of ($x_5_*) and 1 of ($x_1_*))) or
            ((1 of ($x_10_*) and 1 of ($x_5_*) and 1 of ($x_2_*))) or
            ((1 of ($x_10_*) and 1 of ($x_5_*) and 1 of ($x_3_*))) or
            ((1 of ($x_10_*) and 2 of ($x_5_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_Horst_C_2147602381_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Horst.gen!C"
        threat_id = "2147602381"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Horst"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {b9 aa 05 00 00 66 9c (??|?? ??|?? ?? ??|?? ?? ?? ??|?? ?? ?? ?? ??|?? ?? ?? ?? ?? ??|?? ?? ?? ?? ?? ?? ??|?? ?? ?? ?? ?? ?? ?? ??|?? ?? ?? ?? ?? ?? ?? ?? ??|?? ?? ?? ?? ?? ?? ?? ?? ?? ??|?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ??|?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ??|?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ??|?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ??|?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ??) c6 (82|86) a8 05 00 00 0a [0-32] c6 (82|86) a9 05 00 00 00 66 9c (??|?? ??|?? ?? ??|?? ?? ?? ??|?? ?? ?? ?? ??|?? ?? ?? ?? ?? ??|?? ?? ?? ?? ?? ?? ??|?? ?? ?? ?? ?? ?? ?? ??|?? ?? ?? ?? ?? ?? ?? ?? ??|?? ?? ?? ?? ?? ?? ?? ?? ?? ??|?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ??|?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ??|?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ??|?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ??|?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ??) 33 ?? 85 ?? 7e ?? [0-32] 80 34}  //weight: 1, accuracy: Low
        $x_1_2 = {b9 aa 05 00 00 66 9c [0-32] c6 (82|86) a8 05 00 00 0a c6 (82|86) a9 05 00 00 00 [0-16] 33 ?? 85 ?? 7e ?? [0-4] 80 34}  //weight: 1, accuracy: Low
        $x_1_3 = {b9 aa 05 00 00 3b c1 7e 10 8b c1 c6 86 a8 05 00 00 0a c6 86 a9 05 00 00 00 33 ?? 85 ?? 7e ?? 80 34}  //weight: 1, accuracy: Low
        $x_1_4 = {be aa 05 00 00 66 9c (??|?? ??|?? ?? ??|?? ?? ?? ??|?? ?? ?? ?? ??|?? ?? ?? ?? ?? ??|?? ?? ?? ?? ?? ?? ??|?? ?? ?? ?? ?? ?? ?? ??|?? ?? ?? ?? ?? ?? ?? ?? ??|?? ?? ?? ?? ?? ?? ?? ?? ?? ??|?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ??|?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ??|?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ??|?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ??|?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ??|?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ??|?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ??|?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ??|?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ??|?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ??|?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ??|?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ??|?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ??|?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ??|?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ??|?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ??|?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ??|?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ??|?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ??|?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ??|?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ??) e8 ?? ?? ?? ?? c6 87 a8 05 00 00 0a 66 9c (??|?? ??|?? ?? ??|?? ?? ?? ??|?? ?? ?? ?? ??|?? ?? ?? ?? ?? ??|?? ?? ?? ?? ?? ?? ??|?? ?? ?? ?? ?? ?? ?? ??|?? ?? ?? ?? ?? ?? ?? ?? ??|?? ?? ?? ?? ?? ?? ?? ?? ?? ??|?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ??|?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ??|?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ??|?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ??|?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ??|?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ??|?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ??|?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ??|?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ??|?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ??|?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ??|?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ??|?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ??|?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ??|?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ??|?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ??|?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ??|?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ??|?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ??|?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ??|?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ??) (88 8f a9 05|c6 87 a9 05 00) 66 9c (??|?? ??|?? ?? ??|?? ?? ?? ??|?? ?? ?? ?? ??|?? ?? ?? ?? ?? ??|?? ?? ?? ?? ?? ?? ??|?? ?? ?? ?? ?? ?? ?? ??|?? ?? ?? ?? ?? ?? ?? ?? ??|?? ?? ?? ?? ?? ?? ?? ?? ?? ??|?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ??|?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ??|?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ??|?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ??|?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ??) [0-1] 33 ?? 85 ?? [0-1] 7e [0-32] 80 34}  //weight: 1, accuracy: Low
        $x_1_5 = {ba aa 05 00 00 66 9c (??|?? ??|?? ?? ??|?? ?? ?? ??|?? ?? ?? ?? ??|?? ?? ?? ?? ?? ??|?? ?? ?? ?? ?? ?? ??|?? ?? ?? ?? ?? ?? ?? ??|?? ?? ?? ?? ?? ?? ?? ?? ??|?? ?? ?? ?? ?? ?? ?? ?? ?? ??|?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ??|?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ??|?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ??|?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ??|?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ??|?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ??|?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ??|?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ??|?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ??|?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ??|?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ??|?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ??|?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ??|?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ??|?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ??|?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ??|?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ??|?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ??|?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ??|?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ??|?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ??|?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ??|?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ??|?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ??|?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ??|?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ??|?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ??|?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ??|?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ??|?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ??|?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ??|?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ??|?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ??|?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ??|?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ??|?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ??|?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ??) c6 86 a8 05 00 00 0a 66 9c (??|?? ??|?? ?? ??|?? ?? ?? ??|?? ?? ?? ?? ??|?? ?? ?? ?? ?? ??|?? ?? ?? ?? ?? ?? ??|?? ?? ?? ?? ?? ?? ?? ??|?? ?? ?? ?? ?? ?? ?? ?? ??|?? ?? ?? ?? ?? ?? ?? ?? ?? ??|?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ??|?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ??|?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ??|?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ??|?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ??|?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ??|?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ??|?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ??|?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ??|?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ??|?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ??|?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ??|?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ??|?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ??|?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ??|?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ??|?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ??|?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ??|?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ??|?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ??|?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ??) (88 8e a9 05|c6 86 a9 05 00) 66 9c (??|?? ??|?? ?? ??|?? ?? ?? ??|?? ?? ?? ?? ??|?? ?? ?? ?? ?? ??|?? ?? ?? ?? ?? ?? ??|?? ?? ?? ?? ?? ?? ?? ??|?? ?? ?? ?? ?? ?? ?? ?? ??|?? ?? ?? ?? ?? ?? ?? ?? ?? ??|?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ??|?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ??|?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ??|?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ??|?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ??) 33 ?? 85 ?? 7e ?? [0-32] 80 34}  //weight: 1, accuracy: Low
        $x_1_6 = {bf aa 05 00 00 c6 86 a8 05 00 00 0a 88 8e a9 05 00 00 33 ?? 85 ?? 7e ?? [0-4] 80 34}  //weight: 1, accuracy: Low
        $x_1_7 = {b8 aa 05 00 00 c6 82 a8 05 00 00 0a 88 8a a9 05 00 00 33 ?? 85 ?? 7e ?? 80 34}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win32_Horst_C_2147603639_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Horst.C"
        threat_id = "2147603639"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Horst"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "29"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = "\\cvs\\vcprj\\SProj\\Registrar\\" ascii //weight: 10
        $x_10_2 = {7b 25 4c 49 4e 4b 7d [0-4] 3c 2f 53 55 42 4a 3e [0-4] 3c 53 55 42 4a [0-4] 42 4f 44 59 [0-4] 41 54 54 41 43 48 [0-4] 53 55 42 4a}  //weight: 10, accuracy: Low
        $x_5_3 = "ads.zablen.com" ascii //weight: 5
        $x_2_4 = "216.255.178.195" ascii //weight: 2
        $x_2_5 = "/mail/mail.aspx?" ascii //weight: 2
        $x_2_6 = "%s\\Cookies" ascii //weight: 2
        $x_1_7 = "Software\\Microsoft\\Internet Explorer\\Main" ascii //weight: 1
        $x_1_8 = "\\CurrentVersion\\Policies\\Network" ascii //weight: 1
        $x_1_9 = "\\CurrentVersion\\Policies\\Explorer" ascii //weight: 1
        $x_1_10 = "SetWindowsHookExA" ascii //weight: 1
        $x_1_11 = "InternetGetCookieExA" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_10_*) and 2 of ($x_2_*) and 5 of ($x_1_*))) or
            ((2 of ($x_10_*) and 3 of ($x_2_*) and 3 of ($x_1_*))) or
            ((2 of ($x_10_*) and 1 of ($x_5_*) and 4 of ($x_1_*))) or
            ((2 of ($x_10_*) and 1 of ($x_5_*) and 1 of ($x_2_*) and 2 of ($x_1_*))) or
            ((2 of ($x_10_*) and 1 of ($x_5_*) and 2 of ($x_2_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_Horst_D_2147605827_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Horst.D"
        threat_id = "2147605827"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Horst"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "22"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {5c 53 50 72 6f 6a 5c 52 65 67 69 73 74 72 61 72 5c [0-64] 5c 52 65 6c 65 61 73 65 5c [0-32] 2e 70 64 62}  //weight: 10, accuracy: Low
        $x_10_2 = {7b 25 4c 49 4e 4b 7d [0-4] 3c 2f 53 55 42 4a 3e [0-4] 3c 53 55 42 4a [0-4] 42 4f 44 59 [0-4] 41 54 54 41 43 48 [0-4] 53 55 42 4a}  //weight: 10, accuracy: Low
        $x_5_3 = "addCookie Error" ascii //weight: 5
        $x_5_4 = "getMailsStatus Error" ascii //weight: 5
        $x_5_5 = "getRequestIdFromCookies Error" ascii //weight: 5
        $x_1_6 = "Software\\Microsoft\\Windows\\CurrentVersion\\Internet Settings" ascii //weight: 1
        $x_1_7 = {69 6e 6e 65 72 5f 78 6d 6c 00 00 00 74 61 67 5f 6e 61 6d 65}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_10_*) and 2 of ($x_5_*) and 2 of ($x_1_*))) or
            ((1 of ($x_10_*) and 3 of ($x_5_*))) or
            ((2 of ($x_10_*) and 2 of ($x_1_*))) or
            ((2 of ($x_10_*) and 1 of ($x_5_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_Horst_D_2147608074_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Horst.gen!D"
        threat_id = "2147608074"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Horst"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "12"
        strings_accuracy = "High"
    strings:
        $x_10_1 = {c6 03 e3 33 c0 c6 43 05 01 89 45 e1 89 45 e5 88 45 e9 89 45 fc 8b 45 08 8d 88 60 02 00 00}  //weight: 10, accuracy: High
        $x_1_2 = {25 73 5c 25 73 5c 63 61 6c 63 2e 63 66 67 00}  //weight: 1, accuracy: High
        $x_1_3 = {25 73 5c 25 73 5c 63 61 6c 63 2e 65 78 65 00}  //weight: 1, accuracy: High
        $x_1_4 = {25 73 20 2d 20 4e 6f 43 44 20 43 72 61 63 6b 20 4b 65 79 47 65 6e 2e 65 78 65 00}  //weight: 1, accuracy: High
        $x_1_5 = {25 73 20 43 72 61 63 6b 20 50 61 74 63 68 20 53 65 72 69 61 6c 20 4b 65 79 67 65 6e 2e 65 78 65 00}  //weight: 1, accuracy: High
        $x_1_6 = {25 73 20 2b 20 43 52 41 43 4b 20 2b 20 4e 4f 43 44 2e 65 78 65 00}  //weight: 1, accuracy: High
        $x_1_7 = {25 73 20 2b 20 43 52 41 43 4b 20 2b 20 41 43 54 49 56 41 54 4f 52 2e 45 58 45 00}  //weight: 1, accuracy: High
        $x_1_8 = {25 73 20 6b 65 79 67 65 6e 20 63 72 61 63 6b 20 70 61 74 63 68 2e 65 78 65 00}  //weight: 1, accuracy: High
        $x_1_9 = {25 73 5f 63 72 61 63 6b 5f 6b 65 79 67 65 6e 2e 65 78 65 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_10_*) and 2 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_Horst_I_2147608635_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Horst.gen!I"
        threat_id = "2147608635"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Horst"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "12"
        strings_accuracy = "High"
    strings:
        $x_5_1 = "6534C64A-Z454-122E-BFC6-083C2BF4S" ascii //weight: 5
        $x_5_2 = "3645FBCD-ECD2-23D0-BAC4-00DE453DEF6B" ascii //weight: 5
        $x_1_3 = ":*:Enabled:" ascii //weight: 1
        $x_1_4 = "G%y%m%d%H%M%S.%. %p %E %U %C:%c %R:%r %O %I %h %T" ascii //weight: 1
        $x_1_5 = "KAVPersonal50" ascii //weight: 1
        $x_1_6 = "navapsvc" ascii //weight: 1
        $x_1_7 = "Symantec Core LC" ascii //weight: 1
        $x_1_8 = "SAVScan" ascii //weight: 1
        $x_1_9 = "kavsvc" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_5_*) and 7 of ($x_1_*))) or
            ((2 of ($x_5_*) and 2 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_Horst_G_2147608636_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Horst.gen!G"
        threat_id = "2147608636"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Horst"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_3_1 = {8d 4c 24 24 c6 44 24 48 01 c7 44 24 3c 0f 00 00 00 89 5c 24 38 88 5c 24 28 e8 ?? f3 ff ff}  //weight: 3, accuracy: Low
        $x_3_2 = {8d 94 24 54 04 00 00 52 8d 84 24 40 01 00 00 50 68 ?? ?? ?? ?? 68 ?? ?? ?? ?? 8b ce e8 ?? ?? ?? ?? 6a 02}  //weight: 3, accuracy: Low
        $x_1_3 = {65 72 31 3d 62 61 63 26 64 3d 00 3f 65 72 6f 6b 3d 31 26 64 3d 00}  //weight: 1, accuracy: High
        $x_1_4 = {66 72 69 65 6e 64 69 64 3d 00 00 00 27 29 3b 00}  //weight: 1, accuracy: High
        $x_1_5 = "E40D541BB0-35C6A3D262-7DA9630DD9-B2CFD353A3" ascii //weight: 1
        $x_1_6 = {68 6d 75 6e 6d 6c 32 30 64 6c 2e 65 78 65 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_3_*) and 2 of ($x_1_*))) or
            ((2 of ($x_3_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_Horst_H_2147608637_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Horst.gen!H"
        threat_id = "2147608637"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Horst"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_4_1 = {6a 01 6a 03 8d 4c 24 30 aa e8 87 fd ff ff 68 04 01 00 00 8d 84 24 b4 00 00 00 50 68 ?? ?? 45 00 89 9c 24 d8 01 00 00}  //weight: 4, accuracy: Low
        $x_1_2 = {68 74 73 74 66 6c 64 2e 74 6d 70 00}  //weight: 1, accuracy: High
        $x_1_3 = {3f 73 3d 37 26 69 64 3d 00}  //weight: 1, accuracy: High
        $x_1_4 = "getFriends Error" ascii //weight: 1
        $x_1_5 = {66 72 69 65 6e 64 73 5f 77 72 61 70 70 65 72 00}  //weight: 1, accuracy: High
        $x_1_6 = {46 72 69 65 6e 64 73 4c 69 73 74 50 61 67 65 00}  //weight: 1, accuracy: High
        $x_1_7 = {71 75 65 73 74 61 6e 73 77 65 72 00}  //weight: 1, accuracy: High
        $x_1_8 = {46 00 61 00 63 00 65 00 62 00 6f 00 6f 00 6b 00 20 00 7c 00 20 00 48 00 6f 00 6d 00 65 00 00 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((6 of ($x_1_*))) or
            ((1 of ($x_4_*) and 2 of ($x_1_*))) or
            (all of ($x*))
        )
}


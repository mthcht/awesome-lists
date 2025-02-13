rule Worm_Win32_Bagle_A_2147573939_0
{
    meta:
        author = "defender2yara"
        detection_name = "Worm:Win32/Bagle.gen!A"
        threat_id = "2147573939"
        type = "Worm"
        platform = "Win32: Windows 32-bit platform"
        family = "Bagle"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "SOFTWARE\\Windows2000" ascii //weight: 1
        $x_1_2 = "SOFTWARE\\DateTime" ascii //weight: 1
        $x_1_3 = "MAIL FROM:<%s>" ascii //weight: 1
        $x_1_4 = "RCPT TO:<%s>" ascii //weight: 1
        $x_1_5 = "%%].exe\"" ascii //weight: 1
        $x_1_6 = "Message-ID: <%s%s>" ascii //weight: 1
        $x_1_7 = {54 6f 3a 20 [0-1] 25 73}  //weight: 1, accuracy: Low
        $x_1_8 = "if exist %1 goto l" ascii //weight: 1
        $x_1_9 = "NUPGRADE.EXE" ascii //weight: 1
        $x_1_10 = "[%RAND%]" ascii //weight: 1
        $x_1_11 = "@avp." ascii //weight: 1
        $x_1_12 = "151.201.0.39" ascii //weight: 1
        $x_1_13 = {57 69 6e 64 6f 77 6e 20 [0-8] 20 42 65 74 61 20 4c 65 61 6b 2e 65 78 65}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (6 of ($x*))
}

rule Worm_Win32_Bagle_B_2147573940_0
{
    meta:
        author = "defender2yara"
        detection_name = "Worm:Win32/Bagle.gen!B"
        threat_id = "2147573940"
        type = "Worm"
        platform = "Win32: Windows 32-bit platform"
        family = "Bagle"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "9"
        strings_accuracy = "High"
    strings:
        $x_3_1 = {2e 77 61 62 00 2e 74 78 74 00 2e 6d 73 67}  //weight: 3, accuracy: High
        $x_3_2 = {45 48 4c 4f 20 5b 25 73 5d 0d 0a 00 52 53 45 54}  //weight: 3, accuracy: High
        $x_1_3 = "user%lu@" ascii //weight: 1
        $x_1_4 = {2e 6b 72 2f 31 2f 65 6d 6c 2e 70 68 70 00 68 74 74 70 3a 2f 2f}  //weight: 1, accuracy: High
        $x_1_5 = {2e 72 75 2f 31 2f 65 6d 6c 2e 70 68 70 00 68 74 74 70 3a 2f 2f}  //weight: 1, accuracy: High
        $x_1_6 = {2e 6b 72 2f 31 32 33 2e 67 69 66 00 68 74 74 70 3a 2f 2f}  //weight: 1, accuracy: High
        $x_1_7 = {2e 72 75 2f 31 32 33 2e 67 69 66 00 68 74 74 70 3a 2f 2f}  //weight: 1, accuracy: High
        $x_1_8 = "if exist %1 goto l" ascii //weight: 1
        $x_1_9 = "smtp.mail.ru" ascii //weight: 1
        $x_1_10 = "drv_st_key" ascii //weight: 1
        $x_1_11 = "\\hidn" ascii //weight: 1
        $x_1_12 = "m_hook" ascii //weight: 1
        $x_1_13 = "attachment; filename=\"%s%s%s\"" ascii //weight: 1
        $x_1_14 = "-stream; name=\"%s%s%s\"" ascii //weight: 1
        $x_1_15 = "FROM:<%s> SIZE=%l" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((9 of ($x_1_*))) or
            ((1 of ($x_3_*) and 6 of ($x_1_*))) or
            ((2 of ($x_3_*) and 3 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Worm_Win32_Bagle_ACA_2147595110_0
{
    meta:
        author = "defender2yara"
        detection_name = "Worm:Win32/Bagle.ACA"
        threat_id = "2147595110"
        type = "Worm"
        platform = "Win32: Windows 32-bit platform"
        family = "Bagle"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "9"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "FindFirstUrlCacheEntryA" ascii //weight: 1
        $x_1_2 = "GetLogicalDriveStringsA" ascii //weight: 1
        $x_1_3 = "CreateToolhelp32Snapshot" ascii //weight: 1
        $x_3_4 = {c9 c3 5c 00 2a 2e 2a 00 53 59 53 54 45 4d 5c 43}  //weight: 3, accuracy: High
        $x_3_5 = {20 4d 61 6e 61 67 65 72 00 21 5c 3f 3f 5c 43 3a}  //weight: 3, accuracy: High
        $x_3_6 = {74 69 6f 6e 73 00 55 8b ec 81 c4}  //weight: 3, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_3_*) and 3 of ($x_1_*))) or
            ((3 of ($x_3_*))) or
            (all of ($x*))
        )
}

rule Worm_Win32_Bagle_ZHY_2147600928_0
{
    meta:
        author = "defender2yara"
        detection_name = "Worm:Win32/Bagle.ZHY"
        threat_id = "2147600928"
        type = "Worm"
        platform = "Win32: Windows 32-bit platform"
        family = "Bagle"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {46 81 3e 4c 57 45 4b 75 ?? 05 00 00 00 10 89 06 8b ce 2b 4d f8 81 c1 00 0e 00 00 8b 55 ?? 8b 52 ?? 03 55 ?? 8b 82 ?? ?? 00 00 83 82 ?? ?? 00 00 0c 03 45 ?? 05 00 04 00 00 c7 00 00 10 00 00 c7 40 ?? 0c 00 00 00 89 48 ?? 81 48 ?? 00 30 00 00}  //weight: 1, accuracy: Low
        $x_1_2 = {6a 02 6a 00 6a 00 ff 75 0c e8 ?? ?? 00 00 c7 ?? ?? 50 4b 01 02 66 c7 ?? ?? 08 00 66 c7 ?? ?? 14 00 66 c7 ?? ?? 0a 00 66 c7 ?? ?? 01 00 c7 ?? ?? 20 00 00 00 8d ?? ?? 8b ?? ?? b9 2e 00 00 00 f3 a4}  //weight: 1, accuracy: Low
        $x_1_3 = "-S-k-y-N-e-t-" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (2 of ($x*))
}


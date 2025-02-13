rule Worm_Win32_Mytob_2147573829_0
{
    meta:
        author = "defender2yara"
        detection_name = "Worm:Win32/Mytob"
        threat_id = "2147573829"
        type = "Worm"
        platform = "Win32: Windows 32-bit platform"
        family = "Mytob"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "16"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "\\CurrentControlSet\\Services\\SharedAccess" ascii //weight: 1
        $x_1_2 = ".hell." ascii //weight: 1
        $x_2_3 = "[BOT]" ascii //weight: 2
        $x_2_4 = "botzor" ascii //weight: 2
        $x_2_5 = "[x] Connected to" ascii //weight: 2
        $x_2_6 = "[x] Attempting to connect" ascii //weight: 2
        $x_2_7 = "[x] copying to system directory" ascii //weight: 2
        $x_2_8 = "[x] finished copying to system dir" ascii //weight: 2
        $x_2_9 = "[x] cannot copy to system dir" ascii //weight: 2
        $x_2_10 = "[x] cannot start copied file" ascii //weight: 2
        $x_3_11 = "PRIVMSG %s :http(file) downloading..." ascii //weight: 3
        $x_3_12 = "PRIVMSG %s :http(file) downloaded -> (size: %dKB)." ascii //weight: 3
        $x_3_13 = "PRIVMSG %s :updating..." ascii //weight: 3
        $x_3_14 = "PRIVMSG %s :file cannot be executed." ascii //weight: 3
        $x_3_15 = "PRIVMSG %s :current file is already updated." ascii //weight: 3
        $x_2_16 = "botcash" ascii //weight: 2
        $x_3_17 = "PRIVMSG %s :opened file." ascii //weight: 3
        $x_3_18 = "PRIVMSG %s :http(file) cannot be downloaded." ascii //weight: 3
        $x_2_19 = "PRIVMSG %s :Accepted." ascii //weight: 2
        $x_2_20 = "HellBot" ascii //weight: 2
        $x_3_21 = "220 StnyFtpd" ascii //weight: 3
        $x_2_22 = "echo open %s %d >" ascii //weight: 2
        $x_2_23 = "B-O-T-Z-O-R" ascii //weight: 2
        $x_3_24 = "%dKB free [.OS.]: Windows %s" ascii //weight: 3
        $x_5_25 = {31 32 37 2e 30 2e 30 2e 31 09 73 65 63 75 72 69 74 79 72 65 73 70 6f 6e 73 65 2e 73 79 6d 61 6e 74 65 63 2e 63 6f 6d}  //weight: 5, accuracy: High
        $x_5_26 = {31 32 37 2e 30 2e 30 2e 31 09 77 77 77 2e 6d 63 61 66 65 65 2e 63 6f 6d}  //weight: 5, accuracy: High
        $x_5_27 = {99 b9 80 51 01 00 f7 f9 8b c2 99 b9 10 0e 00 00 f7 f9 8b c2 99 b9 3c}  //weight: 5, accuracy: High
        $x_5_28 = {89 85 64 fc ff ff 6a 04 8d 8d 88 fb ff ff 51 6a 04 68 ff ff 00 00 8b 95 64 fc ff ff}  //weight: 5, accuracy: High
        $x_5_29 = {83 c4 08 85 c0 75 1a 6a 00 6a 16 68}  //weight: 5, accuracy: High
        $x_3_30 = "%*s %[^,],%[^,],%[^," ascii //weight: 3
        $x_3_31 = {83 e0 10 85 c0 75 3f 8b 4d fc 51 6a 01 68 00 04 00 00 8d 95 f8 fa ff ff 52 ff 15}  //weight: 3, accuracy: High
        $x_2_32 = "&echo binary >>" ascii //weight: 2
        $x_1_33 = "226 Transfer complete" ascii //weight: 1
        $x_4_34 = "PRIVMSG %s :// -=PNP445=-" ascii //weight: 4
        $x_1_35 = {01 00 00 6a 00 68 00 10 00 00 8d 95}  //weight: 1, accuracy: High
        $x_4_36 = {31 34 30 30 00 00 00 00 31 34 30 32 00 00 00 00 31 34 30 35 00 00 00 00 31 34 30 36}  //weight: 4, accuracy: High
        $x_1_37 = "explorer %s" ascii //weight: 1
        $x_1_38 = "PC NETWORK PROGRAM 1.0" ascii //weight: 1
        $x_3_39 = {4e 49 43 4b 20 25 73 0d 0a 55 53 45 52 20 25 73}  //weight: 3, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((5 of ($x_2_*) and 6 of ($x_1_*))) or
            ((6 of ($x_2_*) and 4 of ($x_1_*))) or
            ((7 of ($x_2_*) and 2 of ($x_1_*))) or
            ((8 of ($x_2_*))) or
            ((1 of ($x_3_*) and 4 of ($x_2_*) and 5 of ($x_1_*))) or
            ((1 of ($x_3_*) and 5 of ($x_2_*) and 3 of ($x_1_*))) or
            ((1 of ($x_3_*) and 6 of ($x_2_*) and 1 of ($x_1_*))) or
            ((1 of ($x_3_*) and 7 of ($x_2_*))) or
            ((2 of ($x_3_*) and 2 of ($x_2_*) and 6 of ($x_1_*))) or
            ((2 of ($x_3_*) and 3 of ($x_2_*) and 4 of ($x_1_*))) or
            ((2 of ($x_3_*) and 4 of ($x_2_*) and 2 of ($x_1_*))) or
            ((2 of ($x_3_*) and 5 of ($x_2_*))) or
            ((3 of ($x_3_*) and 1 of ($x_2_*) and 5 of ($x_1_*))) or
            ((3 of ($x_3_*) and 2 of ($x_2_*) and 3 of ($x_1_*))) or
            ((3 of ($x_3_*) and 3 of ($x_2_*) and 1 of ($x_1_*))) or
            ((3 of ($x_3_*) and 4 of ($x_2_*))) or
            ((4 of ($x_3_*) and 4 of ($x_1_*))) or
            ((4 of ($x_3_*) and 1 of ($x_2_*) and 2 of ($x_1_*))) or
            ((4 of ($x_3_*) and 2 of ($x_2_*))) or
            ((5 of ($x_3_*) and 1 of ($x_1_*))) or
            ((5 of ($x_3_*) and 1 of ($x_2_*))) or
            ((6 of ($x_3_*))) or
            ((1 of ($x_4_*) and 3 of ($x_2_*) and 6 of ($x_1_*))) or
            ((1 of ($x_4_*) and 4 of ($x_2_*) and 4 of ($x_1_*))) or
            ((1 of ($x_4_*) and 5 of ($x_2_*) and 2 of ($x_1_*))) or
            ((1 of ($x_4_*) and 6 of ($x_2_*))) or
            ((1 of ($x_4_*) and 1 of ($x_3_*) and 2 of ($x_2_*) and 5 of ($x_1_*))) or
            ((1 of ($x_4_*) and 1 of ($x_3_*) and 3 of ($x_2_*) and 3 of ($x_1_*))) or
            ((1 of ($x_4_*) and 1 of ($x_3_*) and 4 of ($x_2_*) and 1 of ($x_1_*))) or
            ((1 of ($x_4_*) and 1 of ($x_3_*) and 5 of ($x_2_*))) or
            ((1 of ($x_4_*) and 2 of ($x_3_*) and 6 of ($x_1_*))) or
            ((1 of ($x_4_*) and 2 of ($x_3_*) and 1 of ($x_2_*) and 4 of ($x_1_*))) or
            ((1 of ($x_4_*) and 2 of ($x_3_*) and 2 of ($x_2_*) and 2 of ($x_1_*))) or
            ((1 of ($x_4_*) and 2 of ($x_3_*) and 3 of ($x_2_*))) or
            ((1 of ($x_4_*) and 3 of ($x_3_*) and 3 of ($x_1_*))) or
            ((1 of ($x_4_*) and 3 of ($x_3_*) and 1 of ($x_2_*) and 1 of ($x_1_*))) or
            ((1 of ($x_4_*) and 3 of ($x_3_*) and 2 of ($x_2_*))) or
            ((1 of ($x_4_*) and 4 of ($x_3_*))) or
            ((2 of ($x_4_*) and 1 of ($x_2_*) and 6 of ($x_1_*))) or
            ((2 of ($x_4_*) and 2 of ($x_2_*) and 4 of ($x_1_*))) or
            ((2 of ($x_4_*) and 3 of ($x_2_*) and 2 of ($x_1_*))) or
            ((2 of ($x_4_*) and 4 of ($x_2_*))) or
            ((2 of ($x_4_*) and 1 of ($x_3_*) and 5 of ($x_1_*))) or
            ((2 of ($x_4_*) and 1 of ($x_3_*) and 1 of ($x_2_*) and 3 of ($x_1_*))) or
            ((2 of ($x_4_*) and 1 of ($x_3_*) and 2 of ($x_2_*) and 1 of ($x_1_*))) or
            ((2 of ($x_4_*) and 1 of ($x_3_*) and 3 of ($x_2_*))) or
            ((2 of ($x_4_*) and 2 of ($x_3_*) and 2 of ($x_1_*))) or
            ((2 of ($x_4_*) and 2 of ($x_3_*) and 1 of ($x_2_*))) or
            ((2 of ($x_4_*) and 3 of ($x_3_*))) or
            ((1 of ($x_5_*) and 3 of ($x_2_*) and 5 of ($x_1_*))) or
            ((1 of ($x_5_*) and 4 of ($x_2_*) and 3 of ($x_1_*))) or
            ((1 of ($x_5_*) and 5 of ($x_2_*) and 1 of ($x_1_*))) or
            ((1 of ($x_5_*) and 6 of ($x_2_*))) or
            ((1 of ($x_5_*) and 1 of ($x_3_*) and 1 of ($x_2_*) and 6 of ($x_1_*))) or
            ((1 of ($x_5_*) and 1 of ($x_3_*) and 2 of ($x_2_*) and 4 of ($x_1_*))) or
            ((1 of ($x_5_*) and 1 of ($x_3_*) and 3 of ($x_2_*) and 2 of ($x_1_*))) or
            ((1 of ($x_5_*) and 1 of ($x_3_*) and 4 of ($x_2_*))) or
            ((1 of ($x_5_*) and 2 of ($x_3_*) and 5 of ($x_1_*))) or
            ((1 of ($x_5_*) and 2 of ($x_3_*) and 1 of ($x_2_*) and 3 of ($x_1_*))) or
            ((1 of ($x_5_*) and 2 of ($x_3_*) and 2 of ($x_2_*) and 1 of ($x_1_*))) or
            ((1 of ($x_5_*) and 2 of ($x_3_*) and 3 of ($x_2_*))) or
            ((1 of ($x_5_*) and 3 of ($x_3_*) and 2 of ($x_1_*))) or
            ((1 of ($x_5_*) and 3 of ($x_3_*) and 1 of ($x_2_*))) or
            ((1 of ($x_5_*) and 4 of ($x_3_*))) or
            ((1 of ($x_5_*) and 1 of ($x_4_*) and 1 of ($x_2_*) and 5 of ($x_1_*))) or
            ((1 of ($x_5_*) and 1 of ($x_4_*) and 2 of ($x_2_*) and 3 of ($x_1_*))) or
            ((1 of ($x_5_*) and 1 of ($x_4_*) and 3 of ($x_2_*) and 1 of ($x_1_*))) or
            ((1 of ($x_5_*) and 1 of ($x_4_*) and 4 of ($x_2_*))) or
            ((1 of ($x_5_*) and 1 of ($x_4_*) and 1 of ($x_3_*) and 4 of ($x_1_*))) or
            ((1 of ($x_5_*) and 1 of ($x_4_*) and 1 of ($x_3_*) and 1 of ($x_2_*) and 2 of ($x_1_*))) or
            ((1 of ($x_5_*) and 1 of ($x_4_*) and 1 of ($x_3_*) and 2 of ($x_2_*))) or
            ((1 of ($x_5_*) and 1 of ($x_4_*) and 2 of ($x_3_*) and 1 of ($x_1_*))) or
            ((1 of ($x_5_*) and 1 of ($x_4_*) and 2 of ($x_3_*) and 1 of ($x_2_*))) or
            ((1 of ($x_5_*) and 1 of ($x_4_*) and 3 of ($x_3_*))) or
            ((1 of ($x_5_*) and 2 of ($x_4_*) and 3 of ($x_1_*))) or
            ((1 of ($x_5_*) and 2 of ($x_4_*) and 1 of ($x_2_*) and 1 of ($x_1_*))) or
            ((1 of ($x_5_*) and 2 of ($x_4_*) and 2 of ($x_2_*))) or
            ((1 of ($x_5_*) and 2 of ($x_4_*) and 1 of ($x_3_*))) or
            ((2 of ($x_5_*) and 6 of ($x_1_*))) or
            ((2 of ($x_5_*) and 1 of ($x_2_*) and 4 of ($x_1_*))) or
            ((2 of ($x_5_*) and 2 of ($x_2_*) and 2 of ($x_1_*))) or
            ((2 of ($x_5_*) and 3 of ($x_2_*))) or
            ((2 of ($x_5_*) and 1 of ($x_3_*) and 3 of ($x_1_*))) or
            ((2 of ($x_5_*) and 1 of ($x_3_*) and 1 of ($x_2_*) and 1 of ($x_1_*))) or
            ((2 of ($x_5_*) and 1 of ($x_3_*) and 2 of ($x_2_*))) or
            ((2 of ($x_5_*) and 2 of ($x_3_*))) or
            ((2 of ($x_5_*) and 1 of ($x_4_*) and 2 of ($x_1_*))) or
            ((2 of ($x_5_*) and 1 of ($x_4_*) and 1 of ($x_2_*))) or
            ((2 of ($x_5_*) and 1 of ($x_4_*) and 1 of ($x_3_*))) or
            ((2 of ($x_5_*) and 2 of ($x_4_*))) or
            ((3 of ($x_5_*) and 1 of ($x_1_*))) or
            ((3 of ($x_5_*) and 1 of ($x_2_*))) or
            ((3 of ($x_5_*) and 1 of ($x_3_*))) or
            ((3 of ($x_5_*) and 1 of ($x_4_*))) or
            ((4 of ($x_5_*))) or
            (all of ($x*))
        )
}

rule Worm_Win32_Mytob_2147573875_0
{
    meta:
        author = "defender2yara"
        detection_name = "Worm:Win32/Mytob"
        threat_id = "2147573875"
        type = "Worm"
        platform = "Win32: Windows 32-bit platform"
        family = "Mytob"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {4d 79 52 65 61 6c 4e 61 6d 65 [0-16] 4e 54 53 68 65 6c 6c 20 54 61 73 6b 6d 61 6e 20 53 74 61 72 74 75 70 20 4d 75 74 65 78 [0-16] 5c 74 61 73 6b 6d 67 72 2e 65 78 65 [0-16] 75 73 65 72 33 32 2e 64 6c 6c [0-16] 50 72 6f 67 6d 61 6e [0-16] 50 72 6f 67 72 61 6d 20 4d 61 6e 61 67 65 72 [0-16] 4f 55 54 50 4f 53 54}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Worm_Win32_Mytob_N_2147594715_0
{
    meta:
        author = "defender2yara"
        detection_name = "Worm:Win32/Mytob.N"
        threat_id = "2147594715"
        type = "Worm"
        platform = "Win32: Windows 32-bit platform"
        family = "Mytob"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "http://www.papaop.com/Msifile5/" wide //weight: 1
        $x_1_2 = "1037.exe" wide //weight: 1
        $x_1_3 = "eqifa002.exe" wide //weight: 1
        $x_1_4 = "20262.exe" wide //weight: 1
        $x_1_5 = "ShellExecuteA" ascii //weight: 1
        $x_1_6 = "DownloadFile" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (5 of ($x*))
}


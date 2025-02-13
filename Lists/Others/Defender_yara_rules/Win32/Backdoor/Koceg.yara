rule Backdoor_Win32_Koceg_A_2147602234_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Koceg.gen!A"
        threat_id = "2147602234"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Koceg"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_4_1 = {83 bd fc fe ff ff ?? (73 ??|0f 83 ?? ??) 8b 85 fc fe ff ff ff 34 85 ?? ?? ?? 00 8d 85 00 ff ff ff 50 (e8|ff 15)}  //weight: 4, accuracy: Low
        $x_2_2 = {8d 85 00 ff ff ff 50 ff 15 ?? ?? ?? ?? 68 1a 00 83 bd ?? ?? ff ff ?? 0f 83 ?? 00 00 00 8b 85 ?? ?? ff ff ff 34 85 ?? ?? ?? 00}  //weight: 2, accuracy: Low
        $x_2_3 = {59 3d 80 69 00 00 75 08 8d 85 ?? ?? ff ff eb 19 8d 85 ?? ?? ff ff 50 ff b5 ?? ?? ff ff}  //weight: 2, accuracy: Low
        $x_1_4 = {eb 09 8b 45 fc 83 c0 01 89 45 fc 8b 4d 08 51 (e8 ?? ?? 00 00 83|ff 15 ?? ?? ?? ??) 39 45 fc ?? 16 8b 55 08 03 55 fc 0f be 02 (83 f0 ??|33) 8b 4d 08 03 4d fc 88 01 eb}  //weight: 1, accuracy: Low
        $x_1_5 = {70 72 6f 63 5f 6b 69 6c 6c 00}  //weight: 1, accuracy: High
        $x_1_6 = {70 72 6f 63 5f 72 75 6e 00}  //weight: 1, accuracy: High
        $x_2_7 = {6d 61 6e 64 61 2e 70 68 70 00}  //weight: 2, accuracy: High
        $x_1_8 = {73 79 73 70 72 6f 63 2e 73 79 73 00}  //weight: 1, accuracy: High
        $x_1_9 = {41 64 64 20 74 6f 20 6b 69 6c 6c 20 25 73 00}  //weight: 1, accuracy: High
        $x_1_10 = {6d 69 6e 69 5f 61 76 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((4 of ($x_1_*))) or
            ((1 of ($x_2_*) and 2 of ($x_1_*))) or
            ((2 of ($x_2_*))) or
            ((1 of ($x_4_*))) or
            (all of ($x*))
        )
}

rule Backdoor_Win32_Koceg_B_2147602235_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Koceg.B"
        threat_id = "2147602235"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Koceg"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {83 f8 6e 75 0d ff 75 10 ff 75 0c e8 ?? ?? ff ff 59 59 ff b5 ?? f7 ff ff ff 15 ?? ?? ?? ?? 0f b7 c0 83 f8 15 0f 85 ?? 01 00 00 8b 45 0c 0f be 00 83 f8 55 75 58}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_Win32_Koceg_B_2147605903_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Koceg.gen!B"
        threat_id = "2147605903"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Koceg"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "60"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "ntuser" ascii //weight: 1
        $x_1_2 = "XPTPSW" ascii //weight: 1
        $x_1_3 = "_controlfp" ascii //weight: 1
        $x_1_4 = "%%%02X" ascii //weight: 1
        $x_1_5 = "ImagePath" ascii //weight: 1
        $x_1_6 = "cftmon.exe" ascii //weight: 1
        $x_1_7 = "wininet.dll" ascii //weight: 1
        $x_1_8 = "spools.exe" ascii //weight: 1
        $x_1_9 = "wininet." wide //weight: 1
        $x_1_10 = ".extra" ascii //weight: 1
        $x_1_11 = "ftp33.dll" ascii //weight: 1
        $x_1_12 = "\\exefile\\shell\\open\\command\\" ascii //weight: 1
        $x_2_13 = "<form method=" ascii //weight: 2
        $x_1_14 = "InternetOpenUrlA" ascii //weight: 1
        $x_1_15 = "strcmp" ascii //weight: 1
        $x_1_16 = "_initterm" ascii //weight: 1
        $x_1_17 = "strlen" ascii //weight: 1
        $x_1_18 = "_strdup" ascii //weight: 1
        $x_1_19 = "memset" ascii //weight: 1
        $x_1_20 = "_strcmpi" ascii //weight: 1
        $x_1_21 = "StartupInfo" ascii //weight: 1
        $x_1_22 = "strtok" ascii //weight: 1
        $x_1_23 = "__setusermatherr" ascii //weight: 1
        $x_1_24 = "toupper" ascii //weight: 1
        $x_1_25 = "Software\\Microsoft\\Windows\\CurrentVersion\\Run\\" ascii //weight: 1
        $x_1_26 = "\\Local Settings\\Application Data\\" ascii //weight: 1
        $x_1_27 = "\\drivers\\" ascii //weight: 1
        $x_1_28 = "SYSTEM\\CurrentControlSet\\Services\\Schedule" ascii //weight: 1
        $x_2_29 = "GET %s HTTP/1.1" ascii //weight: 2
        $x_1_30 = "Content-Type: application/x-www-form-urlencoded" ascii //weight: 1
        $x_1_31 = "Content-length: %d" ascii //weight: 1
        $x_1_32 = "Host: %s" ascii //weight: 1
        $x_2_33 = "POST %s HTTP/1.1" ascii //weight: 2
        $x_3_34 = "rm+ion" ascii //weight: 3
        $x_2_35 = "http://fewfwe.com/" ascii //weight: 2
        $x_2_36 = "http://fewfwe.net/" ascii //weight: 2
        $x_10_37 = "manda.php" ascii //weight: 10
        $x_5_38 = "\\mpr.dat" ascii //weight: 5
        $x_10_39 = "\\cs.dat" ascii //weight: 10
        $x_5_40 = "data.php" ascii //weight: 5
        $x_10_41 = "c:\\stop" ascii //weight: 10
        $x_5_42 = "\\mpr2.dat" ascii //weight: 5
        $x_2_43 = "gudug,amo-" ascii //weight: 2
        $x_10_44 = "mpz.tmp" ascii //weight: 10
        $x_3_45 = "%s?id=%s&l=%s" ascii //weight: 3
        $x_2_46 = "0\\1b1" ascii //weight: 2
        $x_2_47 = "\"0.080" ascii //weight: 2
        $x_3_48 = " \"%1\" %*" ascii //weight: 3
        $x_4_49 = "vbs.php" ascii //weight: 4
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_5_*) and 3 of ($x_3_*) and 8 of ($x_2_*) and 30 of ($x_1_*))) or
            ((1 of ($x_5_*) and 1 of ($x_4_*) and 2 of ($x_3_*) and 8 of ($x_2_*) and 29 of ($x_1_*))) or
            ((1 of ($x_5_*) and 1 of ($x_4_*) and 3 of ($x_3_*) and 6 of ($x_2_*) and 30 of ($x_1_*))) or
            ((1 of ($x_5_*) and 1 of ($x_4_*) and 3 of ($x_3_*) and 7 of ($x_2_*) and 28 of ($x_1_*))) or
            ((1 of ($x_5_*) and 1 of ($x_4_*) and 3 of ($x_3_*) and 8 of ($x_2_*) and 26 of ($x_1_*))) or
            ((2 of ($x_5_*) and 2 of ($x_3_*) and 7 of ($x_2_*) and 30 of ($x_1_*))) or
            ((2 of ($x_5_*) and 2 of ($x_3_*) and 8 of ($x_2_*) and 28 of ($x_1_*))) or
            ((2 of ($x_5_*) and 3 of ($x_3_*) and 6 of ($x_2_*) and 29 of ($x_1_*))) or
            ((2 of ($x_5_*) and 3 of ($x_3_*) and 7 of ($x_2_*) and 27 of ($x_1_*))) or
            ((2 of ($x_5_*) and 3 of ($x_3_*) and 8 of ($x_2_*) and 25 of ($x_1_*))) or
            ((2 of ($x_5_*) and 1 of ($x_4_*) and 8 of ($x_2_*) and 30 of ($x_1_*))) or
            ((2 of ($x_5_*) and 1 of ($x_4_*) and 1 of ($x_3_*) and 7 of ($x_2_*) and 29 of ($x_1_*))) or
            ((2 of ($x_5_*) and 1 of ($x_4_*) and 1 of ($x_3_*) and 8 of ($x_2_*) and 27 of ($x_1_*))) or
            ((2 of ($x_5_*) and 1 of ($x_4_*) and 2 of ($x_3_*) and 5 of ($x_2_*) and 30 of ($x_1_*))) or
            ((2 of ($x_5_*) and 1 of ($x_4_*) and 2 of ($x_3_*) and 6 of ($x_2_*) and 28 of ($x_1_*))) or
            ((2 of ($x_5_*) and 1 of ($x_4_*) and 2 of ($x_3_*) and 7 of ($x_2_*) and 26 of ($x_1_*))) or
            ((2 of ($x_5_*) and 1 of ($x_4_*) and 2 of ($x_3_*) and 8 of ($x_2_*) and 24 of ($x_1_*))) or
            ((2 of ($x_5_*) and 1 of ($x_4_*) and 3 of ($x_3_*) and 4 of ($x_2_*) and 29 of ($x_1_*))) or
            ((2 of ($x_5_*) and 1 of ($x_4_*) and 3 of ($x_3_*) and 5 of ($x_2_*) and 27 of ($x_1_*))) or
            ((2 of ($x_5_*) and 1 of ($x_4_*) and 3 of ($x_3_*) and 6 of ($x_2_*) and 25 of ($x_1_*))) or
            ((2 of ($x_5_*) and 1 of ($x_4_*) and 3 of ($x_3_*) and 7 of ($x_2_*) and 23 of ($x_1_*))) or
            ((2 of ($x_5_*) and 1 of ($x_4_*) and 3 of ($x_3_*) and 8 of ($x_2_*) and 21 of ($x_1_*))) or
            ((3 of ($x_5_*) and 8 of ($x_2_*) and 29 of ($x_1_*))) or
            ((3 of ($x_5_*) and 1 of ($x_3_*) and 6 of ($x_2_*) and 30 of ($x_1_*))) or
            ((3 of ($x_5_*) and 1 of ($x_3_*) and 7 of ($x_2_*) and 28 of ($x_1_*))) or
            ((3 of ($x_5_*) and 1 of ($x_3_*) and 8 of ($x_2_*) and 26 of ($x_1_*))) or
            ((3 of ($x_5_*) and 2 of ($x_3_*) and 5 of ($x_2_*) and 29 of ($x_1_*))) or
            ((3 of ($x_5_*) and 2 of ($x_3_*) and 6 of ($x_2_*) and 27 of ($x_1_*))) or
            ((3 of ($x_5_*) and 2 of ($x_3_*) and 7 of ($x_2_*) and 25 of ($x_1_*))) or
            ((3 of ($x_5_*) and 2 of ($x_3_*) and 8 of ($x_2_*) and 23 of ($x_1_*))) or
            ((3 of ($x_5_*) and 3 of ($x_3_*) and 3 of ($x_2_*) and 30 of ($x_1_*))) or
            ((3 of ($x_5_*) and 3 of ($x_3_*) and 4 of ($x_2_*) and 28 of ($x_1_*))) or
            ((3 of ($x_5_*) and 3 of ($x_3_*) and 5 of ($x_2_*) and 26 of ($x_1_*))) or
            ((3 of ($x_5_*) and 3 of ($x_3_*) and 6 of ($x_2_*) and 24 of ($x_1_*))) or
            ((3 of ($x_5_*) and 3 of ($x_3_*) and 7 of ($x_2_*) and 22 of ($x_1_*))) or
            ((3 of ($x_5_*) and 3 of ($x_3_*) and 8 of ($x_2_*) and 20 of ($x_1_*))) or
            ((3 of ($x_5_*) and 1 of ($x_4_*) and 6 of ($x_2_*) and 29 of ($x_1_*))) or
            ((3 of ($x_5_*) and 1 of ($x_4_*) and 7 of ($x_2_*) and 27 of ($x_1_*))) or
            ((3 of ($x_5_*) and 1 of ($x_4_*) and 8 of ($x_2_*) and 25 of ($x_1_*))) or
            ((3 of ($x_5_*) and 1 of ($x_4_*) and 1 of ($x_3_*) and 4 of ($x_2_*) and 30 of ($x_1_*))) or
            ((3 of ($x_5_*) and 1 of ($x_4_*) and 1 of ($x_3_*) and 5 of ($x_2_*) and 28 of ($x_1_*))) or
            ((3 of ($x_5_*) and 1 of ($x_4_*) and 1 of ($x_3_*) and 6 of ($x_2_*) and 26 of ($x_1_*))) or
            ((3 of ($x_5_*) and 1 of ($x_4_*) and 1 of ($x_3_*) and 7 of ($x_2_*) and 24 of ($x_1_*))) or
            ((3 of ($x_5_*) and 1 of ($x_4_*) and 1 of ($x_3_*) and 8 of ($x_2_*) and 22 of ($x_1_*))) or
            ((3 of ($x_5_*) and 1 of ($x_4_*) and 2 of ($x_3_*) and 3 of ($x_2_*) and 29 of ($x_1_*))) or
            ((3 of ($x_5_*) and 1 of ($x_4_*) and 2 of ($x_3_*) and 4 of ($x_2_*) and 27 of ($x_1_*))) or
            ((3 of ($x_5_*) and 1 of ($x_4_*) and 2 of ($x_3_*) and 5 of ($x_2_*) and 25 of ($x_1_*))) or
            ((3 of ($x_5_*) and 1 of ($x_4_*) and 2 of ($x_3_*) and 6 of ($x_2_*) and 23 of ($x_1_*))) or
            ((3 of ($x_5_*) and 1 of ($x_4_*) and 2 of ($x_3_*) and 7 of ($x_2_*) and 21 of ($x_1_*))) or
            ((3 of ($x_5_*) and 1 of ($x_4_*) and 2 of ($x_3_*) and 8 of ($x_2_*) and 19 of ($x_1_*))) or
            ((3 of ($x_5_*) and 1 of ($x_4_*) and 3 of ($x_3_*) and 1 of ($x_2_*) and 30 of ($x_1_*))) or
            ((3 of ($x_5_*) and 1 of ($x_4_*) and 3 of ($x_3_*) and 2 of ($x_2_*) and 28 of ($x_1_*))) or
            ((3 of ($x_5_*) and 1 of ($x_4_*) and 3 of ($x_3_*) and 3 of ($x_2_*) and 26 of ($x_1_*))) or
            ((3 of ($x_5_*) and 1 of ($x_4_*) and 3 of ($x_3_*) and 4 of ($x_2_*) and 24 of ($x_1_*))) or
            ((3 of ($x_5_*) and 1 of ($x_4_*) and 3 of ($x_3_*) and 5 of ($x_2_*) and 22 of ($x_1_*))) or
            ((3 of ($x_5_*) and 1 of ($x_4_*) and 3 of ($x_3_*) and 6 of ($x_2_*) and 20 of ($x_1_*))) or
            ((3 of ($x_5_*) and 1 of ($x_4_*) and 3 of ($x_3_*) and 7 of ($x_2_*) and 18 of ($x_1_*))) or
            ((3 of ($x_5_*) and 1 of ($x_4_*) and 3 of ($x_3_*) and 8 of ($x_2_*) and 16 of ($x_1_*))) or
            ((1 of ($x_10_*) and 2 of ($x_3_*) and 7 of ($x_2_*) and 30 of ($x_1_*))) or
            ((1 of ($x_10_*) and 2 of ($x_3_*) and 8 of ($x_2_*) and 28 of ($x_1_*))) or
            ((1 of ($x_10_*) and 3 of ($x_3_*) and 6 of ($x_2_*) and 29 of ($x_1_*))) or
            ((1 of ($x_10_*) and 3 of ($x_3_*) and 7 of ($x_2_*) and 27 of ($x_1_*))) or
            ((1 of ($x_10_*) and 3 of ($x_3_*) and 8 of ($x_2_*) and 25 of ($x_1_*))) or
            ((1 of ($x_10_*) and 1 of ($x_4_*) and 8 of ($x_2_*) and 30 of ($x_1_*))) or
            ((1 of ($x_10_*) and 1 of ($x_4_*) and 1 of ($x_3_*) and 7 of ($x_2_*) and 29 of ($x_1_*))) or
            ((1 of ($x_10_*) and 1 of ($x_4_*) and 1 of ($x_3_*) and 8 of ($x_2_*) and 27 of ($x_1_*))) or
            ((1 of ($x_10_*) and 1 of ($x_4_*) and 2 of ($x_3_*) and 5 of ($x_2_*) and 30 of ($x_1_*))) or
            ((1 of ($x_10_*) and 1 of ($x_4_*) and 2 of ($x_3_*) and 6 of ($x_2_*) and 28 of ($x_1_*))) or
            ((1 of ($x_10_*) and 1 of ($x_4_*) and 2 of ($x_3_*) and 7 of ($x_2_*) and 26 of ($x_1_*))) or
            ((1 of ($x_10_*) and 1 of ($x_4_*) and 2 of ($x_3_*) and 8 of ($x_2_*) and 24 of ($x_1_*))) or
            ((1 of ($x_10_*) and 1 of ($x_4_*) and 3 of ($x_3_*) and 4 of ($x_2_*) and 29 of ($x_1_*))) or
            ((1 of ($x_10_*) and 1 of ($x_4_*) and 3 of ($x_3_*) and 5 of ($x_2_*) and 27 of ($x_1_*))) or
            ((1 of ($x_10_*) and 1 of ($x_4_*) and 3 of ($x_3_*) and 6 of ($x_2_*) and 25 of ($x_1_*))) or
            ((1 of ($x_10_*) and 1 of ($x_4_*) and 3 of ($x_3_*) and 7 of ($x_2_*) and 23 of ($x_1_*))) or
            ((1 of ($x_10_*) and 1 of ($x_4_*) and 3 of ($x_3_*) and 8 of ($x_2_*) and 21 of ($x_1_*))) or
            ((1 of ($x_10_*) and 1 of ($x_5_*) and 8 of ($x_2_*) and 29 of ($x_1_*))) or
            ((1 of ($x_10_*) and 1 of ($x_5_*) and 1 of ($x_3_*) and 6 of ($x_2_*) and 30 of ($x_1_*))) or
            ((1 of ($x_10_*) and 1 of ($x_5_*) and 1 of ($x_3_*) and 7 of ($x_2_*) and 28 of ($x_1_*))) or
            ((1 of ($x_10_*) and 1 of ($x_5_*) and 1 of ($x_3_*) and 8 of ($x_2_*) and 26 of ($x_1_*))) or
            ((1 of ($x_10_*) and 1 of ($x_5_*) and 2 of ($x_3_*) and 5 of ($x_2_*) and 29 of ($x_1_*))) or
            ((1 of ($x_10_*) and 1 of ($x_5_*) and 2 of ($x_3_*) and 6 of ($x_2_*) and 27 of ($x_1_*))) or
            ((1 of ($x_10_*) and 1 of ($x_5_*) and 2 of ($x_3_*) and 7 of ($x_2_*) and 25 of ($x_1_*))) or
            ((1 of ($x_10_*) and 1 of ($x_5_*) and 2 of ($x_3_*) and 8 of ($x_2_*) and 23 of ($x_1_*))) or
            ((1 of ($x_10_*) and 1 of ($x_5_*) and 3 of ($x_3_*) and 3 of ($x_2_*) and 30 of ($x_1_*))) or
            ((1 of ($x_10_*) and 1 of ($x_5_*) and 3 of ($x_3_*) and 4 of ($x_2_*) and 28 of ($x_1_*))) or
            ((1 of ($x_10_*) and 1 of ($x_5_*) and 3 of ($x_3_*) and 5 of ($x_2_*) and 26 of ($x_1_*))) or
            ((1 of ($x_10_*) and 1 of ($x_5_*) and 3 of ($x_3_*) and 6 of ($x_2_*) and 24 of ($x_1_*))) or
            ((1 of ($x_10_*) and 1 of ($x_5_*) and 3 of ($x_3_*) and 7 of ($x_2_*) and 22 of ($x_1_*))) or
            ((1 of ($x_10_*) and 1 of ($x_5_*) and 3 of ($x_3_*) and 8 of ($x_2_*) and 20 of ($x_1_*))) or
            ((1 of ($x_10_*) and 1 of ($x_5_*) and 1 of ($x_4_*) and 6 of ($x_2_*) and 29 of ($x_1_*))) or
            ((1 of ($x_10_*) and 1 of ($x_5_*) and 1 of ($x_4_*) and 7 of ($x_2_*) and 27 of ($x_1_*))) or
            ((1 of ($x_10_*) and 1 of ($x_5_*) and 1 of ($x_4_*) and 8 of ($x_2_*) and 25 of ($x_1_*))) or
            ((1 of ($x_10_*) and 1 of ($x_5_*) and 1 of ($x_4_*) and 1 of ($x_3_*) and 4 of ($x_2_*) and 30 of ($x_1_*))) or
            ((1 of ($x_10_*) and 1 of ($x_5_*) and 1 of ($x_4_*) and 1 of ($x_3_*) and 5 of ($x_2_*) and 28 of ($x_1_*))) or
            ((1 of ($x_10_*) and 1 of ($x_5_*) and 1 of ($x_4_*) and 1 of ($x_3_*) and 6 of ($x_2_*) and 26 of ($x_1_*))) or
            ((1 of ($x_10_*) and 1 of ($x_5_*) and 1 of ($x_4_*) and 1 of ($x_3_*) and 7 of ($x_2_*) and 24 of ($x_1_*))) or
            ((1 of ($x_10_*) and 1 of ($x_5_*) and 1 of ($x_4_*) and 1 of ($x_3_*) and 8 of ($x_2_*) and 22 of ($x_1_*))) or
            ((1 of ($x_10_*) and 1 of ($x_5_*) and 1 of ($x_4_*) and 2 of ($x_3_*) and 3 of ($x_2_*) and 29 of ($x_1_*))) or
            ((1 of ($x_10_*) and 1 of ($x_5_*) and 1 of ($x_4_*) and 2 of ($x_3_*) and 4 of ($x_2_*) and 27 of ($x_1_*))) or
            ((1 of ($x_10_*) and 1 of ($x_5_*) and 1 of ($x_4_*) and 2 of ($x_3_*) and 5 of ($x_2_*) and 25 of ($x_1_*))) or
            ((1 of ($x_10_*) and 1 of ($x_5_*) and 1 of ($x_4_*) and 2 of ($x_3_*) and 6 of ($x_2_*) and 23 of ($x_1_*))) or
            ((1 of ($x_10_*) and 1 of ($x_5_*) and 1 of ($x_4_*) and 2 of ($x_3_*) and 7 of ($x_2_*) and 21 of ($x_1_*))) or
            ((1 of ($x_10_*) and 1 of ($x_5_*) and 1 of ($x_4_*) and 2 of ($x_3_*) and 8 of ($x_2_*) and 19 of ($x_1_*))) or
            ((1 of ($x_10_*) and 1 of ($x_5_*) and 1 of ($x_4_*) and 3 of ($x_3_*) and 1 of ($x_2_*) and 30 of ($x_1_*))) or
            ((1 of ($x_10_*) and 1 of ($x_5_*) and 1 of ($x_4_*) and 3 of ($x_3_*) and 2 of ($x_2_*) and 28 of ($x_1_*))) or
            ((1 of ($x_10_*) and 1 of ($x_5_*) and 1 of ($x_4_*) and 3 of ($x_3_*) and 3 of ($x_2_*) and 26 of ($x_1_*))) or
            ((1 of ($x_10_*) and 1 of ($x_5_*) and 1 of ($x_4_*) and 3 of ($x_3_*) and 4 of ($x_2_*) and 24 of ($x_1_*))) or
            ((1 of ($x_10_*) and 1 of ($x_5_*) and 1 of ($x_4_*) and 3 of ($x_3_*) and 5 of ($x_2_*) and 22 of ($x_1_*))) or
            ((1 of ($x_10_*) and 1 of ($x_5_*) and 1 of ($x_4_*) and 3 of ($x_3_*) and 6 of ($x_2_*) and 20 of ($x_1_*))) or
            ((1 of ($x_10_*) and 1 of ($x_5_*) and 1 of ($x_4_*) and 3 of ($x_3_*) and 7 of ($x_2_*) and 18 of ($x_1_*))) or
            ((1 of ($x_10_*) and 1 of ($x_5_*) and 1 of ($x_4_*) and 3 of ($x_3_*) and 8 of ($x_2_*) and 16 of ($x_1_*))) or
            ((1 of ($x_10_*) and 2 of ($x_5_*) and 5 of ($x_2_*) and 30 of ($x_1_*))) or
            ((1 of ($x_10_*) and 2 of ($x_5_*) and 6 of ($x_2_*) and 28 of ($x_1_*))) or
            ((1 of ($x_10_*) and 2 of ($x_5_*) and 7 of ($x_2_*) and 26 of ($x_1_*))) or
            ((1 of ($x_10_*) and 2 of ($x_5_*) and 8 of ($x_2_*) and 24 of ($x_1_*))) or
            ((1 of ($x_10_*) and 2 of ($x_5_*) and 1 of ($x_3_*) and 4 of ($x_2_*) and 29 of ($x_1_*))) or
            ((1 of ($x_10_*) and 2 of ($x_5_*) and 1 of ($x_3_*) and 5 of ($x_2_*) and 27 of ($x_1_*))) or
            ((1 of ($x_10_*) and 2 of ($x_5_*) and 1 of ($x_3_*) and 6 of ($x_2_*) and 25 of ($x_1_*))) or
            ((1 of ($x_10_*) and 2 of ($x_5_*) and 1 of ($x_3_*) and 7 of ($x_2_*) and 23 of ($x_1_*))) or
            ((1 of ($x_10_*) and 2 of ($x_5_*) and 1 of ($x_3_*) and 8 of ($x_2_*) and 21 of ($x_1_*))) or
            ((1 of ($x_10_*) and 2 of ($x_5_*) and 2 of ($x_3_*) and 2 of ($x_2_*) and 30 of ($x_1_*))) or
            ((1 of ($x_10_*) and 2 of ($x_5_*) and 2 of ($x_3_*) and 3 of ($x_2_*) and 28 of ($x_1_*))) or
            ((1 of ($x_10_*) and 2 of ($x_5_*) and 2 of ($x_3_*) and 4 of ($x_2_*) and 26 of ($x_1_*))) or
            ((1 of ($x_10_*) and 2 of ($x_5_*) and 2 of ($x_3_*) and 5 of ($x_2_*) and 24 of ($x_1_*))) or
            ((1 of ($x_10_*) and 2 of ($x_5_*) and 2 of ($x_3_*) and 6 of ($x_2_*) and 22 of ($x_1_*))) or
            ((1 of ($x_10_*) and 2 of ($x_5_*) and 2 of ($x_3_*) and 7 of ($x_2_*) and 20 of ($x_1_*))) or
            ((1 of ($x_10_*) and 2 of ($x_5_*) and 2 of ($x_3_*) and 8 of ($x_2_*) and 18 of ($x_1_*))) or
            ((1 of ($x_10_*) and 2 of ($x_5_*) and 3 of ($x_3_*) and 1 of ($x_2_*) and 29 of ($x_1_*))) or
            ((1 of ($x_10_*) and 2 of ($x_5_*) and 3 of ($x_3_*) and 2 of ($x_2_*) and 27 of ($x_1_*))) or
            ((1 of ($x_10_*) and 2 of ($x_5_*) and 3 of ($x_3_*) and 3 of ($x_2_*) and 25 of ($x_1_*))) or
            ((1 of ($x_10_*) and 2 of ($x_5_*) and 3 of ($x_3_*) and 4 of ($x_2_*) and 23 of ($x_1_*))) or
            ((1 of ($x_10_*) and 2 of ($x_5_*) and 3 of ($x_3_*) and 5 of ($x_2_*) and 21 of ($x_1_*))) or
            ((1 of ($x_10_*) and 2 of ($x_5_*) and 3 of ($x_3_*) and 6 of ($x_2_*) and 19 of ($x_1_*))) or
            ((1 of ($x_10_*) and 2 of ($x_5_*) and 3 of ($x_3_*) and 7 of ($x_2_*) and 17 of ($x_1_*))) or
            ((1 of ($x_10_*) and 2 of ($x_5_*) and 3 of ($x_3_*) and 8 of ($x_2_*) and 15 of ($x_1_*))) or
            ((1 of ($x_10_*) and 2 of ($x_5_*) and 1 of ($x_4_*) and 3 of ($x_2_*) and 30 of ($x_1_*))) or
            ((1 of ($x_10_*) and 2 of ($x_5_*) and 1 of ($x_4_*) and 4 of ($x_2_*) and 28 of ($x_1_*))) or
            ((1 of ($x_10_*) and 2 of ($x_5_*) and 1 of ($x_4_*) and 5 of ($x_2_*) and 26 of ($x_1_*))) or
            ((1 of ($x_10_*) and 2 of ($x_5_*) and 1 of ($x_4_*) and 6 of ($x_2_*) and 24 of ($x_1_*))) or
            ((1 of ($x_10_*) and 2 of ($x_5_*) and 1 of ($x_4_*) and 7 of ($x_2_*) and 22 of ($x_1_*))) or
            ((1 of ($x_10_*) and 2 of ($x_5_*) and 1 of ($x_4_*) and 8 of ($x_2_*) and 20 of ($x_1_*))) or
            ((1 of ($x_10_*) and 2 of ($x_5_*) and 1 of ($x_4_*) and 1 of ($x_3_*) and 2 of ($x_2_*) and 29 of ($x_1_*))) or
            ((1 of ($x_10_*) and 2 of ($x_5_*) and 1 of ($x_4_*) and 1 of ($x_3_*) and 3 of ($x_2_*) and 27 of ($x_1_*))) or
            ((1 of ($x_10_*) and 2 of ($x_5_*) and 1 of ($x_4_*) and 1 of ($x_3_*) and 4 of ($x_2_*) and 25 of ($x_1_*))) or
            ((1 of ($x_10_*) and 2 of ($x_5_*) and 1 of ($x_4_*) and 1 of ($x_3_*) and 5 of ($x_2_*) and 23 of ($x_1_*))) or
            ((1 of ($x_10_*) and 2 of ($x_5_*) and 1 of ($x_4_*) and 1 of ($x_3_*) and 6 of ($x_2_*) and 21 of ($x_1_*))) or
            ((1 of ($x_10_*) and 2 of ($x_5_*) and 1 of ($x_4_*) and 1 of ($x_3_*) and 7 of ($x_2_*) and 19 of ($x_1_*))) or
            ((1 of ($x_10_*) and 2 of ($x_5_*) and 1 of ($x_4_*) and 1 of ($x_3_*) and 8 of ($x_2_*) and 17 of ($x_1_*))) or
            ((1 of ($x_10_*) and 2 of ($x_5_*) and 1 of ($x_4_*) and 2 of ($x_3_*) and 30 of ($x_1_*))) or
            ((1 of ($x_10_*) and 2 of ($x_5_*) and 1 of ($x_4_*) and 2 of ($x_3_*) and 1 of ($x_2_*) and 28 of ($x_1_*))) or
            ((1 of ($x_10_*) and 2 of ($x_5_*) and 1 of ($x_4_*) and 2 of ($x_3_*) and 2 of ($x_2_*) and 26 of ($x_1_*))) or
            ((1 of ($x_10_*) and 2 of ($x_5_*) and 1 of ($x_4_*) and 2 of ($x_3_*) and 3 of ($x_2_*) and 24 of ($x_1_*))) or
            ((1 of ($x_10_*) and 2 of ($x_5_*) and 1 of ($x_4_*) and 2 of ($x_3_*) and 4 of ($x_2_*) and 22 of ($x_1_*))) or
            ((1 of ($x_10_*) and 2 of ($x_5_*) and 1 of ($x_4_*) and 2 of ($x_3_*) and 5 of ($x_2_*) and 20 of ($x_1_*))) or
            ((1 of ($x_10_*) and 2 of ($x_5_*) and 1 of ($x_4_*) and 2 of ($x_3_*) and 6 of ($x_2_*) and 18 of ($x_1_*))) or
            ((1 of ($x_10_*) and 2 of ($x_5_*) and 1 of ($x_4_*) and 2 of ($x_3_*) and 7 of ($x_2_*) and 16 of ($x_1_*))) or
            ((1 of ($x_10_*) and 2 of ($x_5_*) and 1 of ($x_4_*) and 2 of ($x_3_*) and 8 of ($x_2_*) and 14 of ($x_1_*))) or
            ((1 of ($x_10_*) and 2 of ($x_5_*) and 1 of ($x_4_*) and 3 of ($x_3_*) and 27 of ($x_1_*))) or
            ((1 of ($x_10_*) and 2 of ($x_5_*) and 1 of ($x_4_*) and 3 of ($x_3_*) and 1 of ($x_2_*) and 25 of ($x_1_*))) or
            ((1 of ($x_10_*) and 2 of ($x_5_*) and 1 of ($x_4_*) and 3 of ($x_3_*) and 2 of ($x_2_*) and 23 of ($x_1_*))) or
            ((1 of ($x_10_*) and 2 of ($x_5_*) and 1 of ($x_4_*) and 3 of ($x_3_*) and 3 of ($x_2_*) and 21 of ($x_1_*))) or
            ((1 of ($x_10_*) and 2 of ($x_5_*) and 1 of ($x_4_*) and 3 of ($x_3_*) and 4 of ($x_2_*) and 19 of ($x_1_*))) or
            ((1 of ($x_10_*) and 2 of ($x_5_*) and 1 of ($x_4_*) and 3 of ($x_3_*) and 5 of ($x_2_*) and 17 of ($x_1_*))) or
            ((1 of ($x_10_*) and 2 of ($x_5_*) and 1 of ($x_4_*) and 3 of ($x_3_*) and 6 of ($x_2_*) and 15 of ($x_1_*))) or
            ((1 of ($x_10_*) and 2 of ($x_5_*) and 1 of ($x_4_*) and 3 of ($x_3_*) and 7 of ($x_2_*) and 13 of ($x_1_*))) or
            ((1 of ($x_10_*) and 2 of ($x_5_*) and 1 of ($x_4_*) and 3 of ($x_3_*) and 8 of ($x_2_*) and 11 of ($x_1_*))) or
            ((1 of ($x_10_*) and 3 of ($x_5_*) and 3 of ($x_2_*) and 29 of ($x_1_*))) or
            ((1 of ($x_10_*) and 3 of ($x_5_*) and 4 of ($x_2_*) and 27 of ($x_1_*))) or
            ((1 of ($x_10_*) and 3 of ($x_5_*) and 5 of ($x_2_*) and 25 of ($x_1_*))) or
            ((1 of ($x_10_*) and 3 of ($x_5_*) and 6 of ($x_2_*) and 23 of ($x_1_*))) or
            ((1 of ($x_10_*) and 3 of ($x_5_*) and 7 of ($x_2_*) and 21 of ($x_1_*))) or
            ((1 of ($x_10_*) and 3 of ($x_5_*) and 8 of ($x_2_*) and 19 of ($x_1_*))) or
            ((1 of ($x_10_*) and 3 of ($x_5_*) and 1 of ($x_3_*) and 1 of ($x_2_*) and 30 of ($x_1_*))) or
            ((1 of ($x_10_*) and 3 of ($x_5_*) and 1 of ($x_3_*) and 2 of ($x_2_*) and 28 of ($x_1_*))) or
            ((1 of ($x_10_*) and 3 of ($x_5_*) and 1 of ($x_3_*) and 3 of ($x_2_*) and 26 of ($x_1_*))) or
            ((1 of ($x_10_*) and 3 of ($x_5_*) and 1 of ($x_3_*) and 4 of ($x_2_*) and 24 of ($x_1_*))) or
            ((1 of ($x_10_*) and 3 of ($x_5_*) and 1 of ($x_3_*) and 5 of ($x_2_*) and 22 of ($x_1_*))) or
            ((1 of ($x_10_*) and 3 of ($x_5_*) and 1 of ($x_3_*) and 6 of ($x_2_*) and 20 of ($x_1_*))) or
            ((1 of ($x_10_*) and 3 of ($x_5_*) and 1 of ($x_3_*) and 7 of ($x_2_*) and 18 of ($x_1_*))) or
            ((1 of ($x_10_*) and 3 of ($x_5_*) and 1 of ($x_3_*) and 8 of ($x_2_*) and 16 of ($x_1_*))) or
            ((1 of ($x_10_*) and 3 of ($x_5_*) and 2 of ($x_3_*) and 29 of ($x_1_*))) or
            ((1 of ($x_10_*) and 3 of ($x_5_*) and 2 of ($x_3_*) and 1 of ($x_2_*) and 27 of ($x_1_*))) or
            ((1 of ($x_10_*) and 3 of ($x_5_*) and 2 of ($x_3_*) and 2 of ($x_2_*) and 25 of ($x_1_*))) or
            ((1 of ($x_10_*) and 3 of ($x_5_*) and 2 of ($x_3_*) and 3 of ($x_2_*) and 23 of ($x_1_*))) or
            ((1 of ($x_10_*) and 3 of ($x_5_*) and 2 of ($x_3_*) and 4 of ($x_2_*) and 21 of ($x_1_*))) or
            ((1 of ($x_10_*) and 3 of ($x_5_*) and 2 of ($x_3_*) and 5 of ($x_2_*) and 19 of ($x_1_*))) or
            ((1 of ($x_10_*) and 3 of ($x_5_*) and 2 of ($x_3_*) and 6 of ($x_2_*) and 17 of ($x_1_*))) or
            ((1 of ($x_10_*) and 3 of ($x_5_*) and 2 of ($x_3_*) and 7 of ($x_2_*) and 15 of ($x_1_*))) or
            ((1 of ($x_10_*) and 3 of ($x_5_*) and 2 of ($x_3_*) and 8 of ($x_2_*) and 13 of ($x_1_*))) or
            ((1 of ($x_10_*) and 3 of ($x_5_*) and 3 of ($x_3_*) and 26 of ($x_1_*))) or
            ((1 of ($x_10_*) and 3 of ($x_5_*) and 3 of ($x_3_*) and 1 of ($x_2_*) and 24 of ($x_1_*))) or
            ((1 of ($x_10_*) and 3 of ($x_5_*) and 3 of ($x_3_*) and 2 of ($x_2_*) and 22 of ($x_1_*))) or
            ((1 of ($x_10_*) and 3 of ($x_5_*) and 3 of ($x_3_*) and 3 of ($x_2_*) and 20 of ($x_1_*))) or
            ((1 of ($x_10_*) and 3 of ($x_5_*) and 3 of ($x_3_*) and 4 of ($x_2_*) and 18 of ($x_1_*))) or
            ((1 of ($x_10_*) and 3 of ($x_5_*) and 3 of ($x_3_*) and 5 of ($x_2_*) and 16 of ($x_1_*))) or
            ((1 of ($x_10_*) and 3 of ($x_5_*) and 3 of ($x_3_*) and 6 of ($x_2_*) and 14 of ($x_1_*))) or
            ((1 of ($x_10_*) and 3 of ($x_5_*) and 3 of ($x_3_*) and 7 of ($x_2_*) and 12 of ($x_1_*))) or
            ((1 of ($x_10_*) and 3 of ($x_5_*) and 3 of ($x_3_*) and 8 of ($x_2_*) and 10 of ($x_1_*))) or
            ((1 of ($x_10_*) and 3 of ($x_5_*) and 1 of ($x_4_*) and 1 of ($x_2_*) and 29 of ($x_1_*))) or
            ((1 of ($x_10_*) and 3 of ($x_5_*) and 1 of ($x_4_*) and 2 of ($x_2_*) and 27 of ($x_1_*))) or
            ((1 of ($x_10_*) and 3 of ($x_5_*) and 1 of ($x_4_*) and 3 of ($x_2_*) and 25 of ($x_1_*))) or
            ((1 of ($x_10_*) and 3 of ($x_5_*) and 1 of ($x_4_*) and 4 of ($x_2_*) and 23 of ($x_1_*))) or
            ((1 of ($x_10_*) and 3 of ($x_5_*) and 1 of ($x_4_*) and 5 of ($x_2_*) and 21 of ($x_1_*))) or
            ((1 of ($x_10_*) and 3 of ($x_5_*) and 1 of ($x_4_*) and 6 of ($x_2_*) and 19 of ($x_1_*))) or
            ((1 of ($x_10_*) and 3 of ($x_5_*) and 1 of ($x_4_*) and 7 of ($x_2_*) and 17 of ($x_1_*))) or
            ((1 of ($x_10_*) and 3 of ($x_5_*) and 1 of ($x_4_*) and 8 of ($x_2_*) and 15 of ($x_1_*))) or
            ((1 of ($x_10_*) and 3 of ($x_5_*) and 1 of ($x_4_*) and 1 of ($x_3_*) and 28 of ($x_1_*))) or
            ((1 of ($x_10_*) and 3 of ($x_5_*) and 1 of ($x_4_*) and 1 of ($x_3_*) and 1 of ($x_2_*) and 26 of ($x_1_*))) or
            ((1 of ($x_10_*) and 3 of ($x_5_*) and 1 of ($x_4_*) and 1 of ($x_3_*) and 2 of ($x_2_*) and 24 of ($x_1_*))) or
            ((1 of ($x_10_*) and 3 of ($x_5_*) and 1 of ($x_4_*) and 1 of ($x_3_*) and 3 of ($x_2_*) and 22 of ($x_1_*))) or
            ((1 of ($x_10_*) and 3 of ($x_5_*) and 1 of ($x_4_*) and 1 of ($x_3_*) and 4 of ($x_2_*) and 20 of ($x_1_*))) or
            ((1 of ($x_10_*) and 3 of ($x_5_*) and 1 of ($x_4_*) and 1 of ($x_3_*) and 5 of ($x_2_*) and 18 of ($x_1_*))) or
            ((1 of ($x_10_*) and 3 of ($x_5_*) and 1 of ($x_4_*) and 1 of ($x_3_*) and 6 of ($x_2_*) and 16 of ($x_1_*))) or
            ((1 of ($x_10_*) and 3 of ($x_5_*) and 1 of ($x_4_*) and 1 of ($x_3_*) and 7 of ($x_2_*) and 14 of ($x_1_*))) or
            ((1 of ($x_10_*) and 3 of ($x_5_*) and 1 of ($x_4_*) and 1 of ($x_3_*) and 8 of ($x_2_*) and 12 of ($x_1_*))) or
            ((1 of ($x_10_*) and 3 of ($x_5_*) and 1 of ($x_4_*) and 2 of ($x_3_*) and 25 of ($x_1_*))) or
            ((1 of ($x_10_*) and 3 of ($x_5_*) and 1 of ($x_4_*) and 2 of ($x_3_*) and 1 of ($x_2_*) and 23 of ($x_1_*))) or
            ((1 of ($x_10_*) and 3 of ($x_5_*) and 1 of ($x_4_*) and 2 of ($x_3_*) and 2 of ($x_2_*) and 21 of ($x_1_*))) or
            ((1 of ($x_10_*) and 3 of ($x_5_*) and 1 of ($x_4_*) and 2 of ($x_3_*) and 3 of ($x_2_*) and 19 of ($x_1_*))) or
            ((1 of ($x_10_*) and 3 of ($x_5_*) and 1 of ($x_4_*) and 2 of ($x_3_*) and 4 of ($x_2_*) and 17 of ($x_1_*))) or
            ((1 of ($x_10_*) and 3 of ($x_5_*) and 1 of ($x_4_*) and 2 of ($x_3_*) and 5 of ($x_2_*) and 15 of ($x_1_*))) or
            ((1 of ($x_10_*) and 3 of ($x_5_*) and 1 of ($x_4_*) and 2 of ($x_3_*) and 6 of ($x_2_*) and 13 of ($x_1_*))) or
            ((1 of ($x_10_*) and 3 of ($x_5_*) and 1 of ($x_4_*) and 2 of ($x_3_*) and 7 of ($x_2_*) and 11 of ($x_1_*))) or
            ((1 of ($x_10_*) and 3 of ($x_5_*) and 1 of ($x_4_*) and 2 of ($x_3_*) and 8 of ($x_2_*) and 9 of ($x_1_*))) or
            ((1 of ($x_10_*) and 3 of ($x_5_*) and 1 of ($x_4_*) and 3 of ($x_3_*) and 22 of ($x_1_*))) or
            ((1 of ($x_10_*) and 3 of ($x_5_*) and 1 of ($x_4_*) and 3 of ($x_3_*) and 1 of ($x_2_*) and 20 of ($x_1_*))) or
            ((1 of ($x_10_*) and 3 of ($x_5_*) and 1 of ($x_4_*) and 3 of ($x_3_*) and 2 of ($x_2_*) and 18 of ($x_1_*))) or
            ((1 of ($x_10_*) and 3 of ($x_5_*) and 1 of ($x_4_*) and 3 of ($x_3_*) and 3 of ($x_2_*) and 16 of ($x_1_*))) or
            ((1 of ($x_10_*) and 3 of ($x_5_*) and 1 of ($x_4_*) and 3 of ($x_3_*) and 4 of ($x_2_*) and 14 of ($x_1_*))) or
            ((1 of ($x_10_*) and 3 of ($x_5_*) and 1 of ($x_4_*) and 3 of ($x_3_*) and 5 of ($x_2_*) and 12 of ($x_1_*))) or
            ((1 of ($x_10_*) and 3 of ($x_5_*) and 1 of ($x_4_*) and 3 of ($x_3_*) and 6 of ($x_2_*) and 10 of ($x_1_*))) or
            ((1 of ($x_10_*) and 3 of ($x_5_*) and 1 of ($x_4_*) and 3 of ($x_3_*) and 7 of ($x_2_*) and 8 of ($x_1_*))) or
            ((1 of ($x_10_*) and 3 of ($x_5_*) and 1 of ($x_4_*) and 3 of ($x_3_*) and 8 of ($x_2_*) and 6 of ($x_1_*))) or
            ((2 of ($x_10_*) and 5 of ($x_2_*) and 30 of ($x_1_*))) or
            ((2 of ($x_10_*) and 6 of ($x_2_*) and 28 of ($x_1_*))) or
            ((2 of ($x_10_*) and 7 of ($x_2_*) and 26 of ($x_1_*))) or
            ((2 of ($x_10_*) and 8 of ($x_2_*) and 24 of ($x_1_*))) or
            ((2 of ($x_10_*) and 1 of ($x_3_*) and 4 of ($x_2_*) and 29 of ($x_1_*))) or
            ((2 of ($x_10_*) and 1 of ($x_3_*) and 5 of ($x_2_*) and 27 of ($x_1_*))) or
            ((2 of ($x_10_*) and 1 of ($x_3_*) and 6 of ($x_2_*) and 25 of ($x_1_*))) or
            ((2 of ($x_10_*) and 1 of ($x_3_*) and 7 of ($x_2_*) and 23 of ($x_1_*))) or
            ((2 of ($x_10_*) and 1 of ($x_3_*) and 8 of ($x_2_*) and 21 of ($x_1_*))) or
            ((2 of ($x_10_*) and 2 of ($x_3_*) and 2 of ($x_2_*) and 30 of ($x_1_*))) or
            ((2 of ($x_10_*) and 2 of ($x_3_*) and 3 of ($x_2_*) and 28 of ($x_1_*))) or
            ((2 of ($x_10_*) and 2 of ($x_3_*) and 4 of ($x_2_*) and 26 of ($x_1_*))) or
            ((2 of ($x_10_*) and 2 of ($x_3_*) and 5 of ($x_2_*) and 24 of ($x_1_*))) or
            ((2 of ($x_10_*) and 2 of ($x_3_*) and 6 of ($x_2_*) and 22 of ($x_1_*))) or
            ((2 of ($x_10_*) and 2 of ($x_3_*) and 7 of ($x_2_*) and 20 of ($x_1_*))) or
            ((2 of ($x_10_*) and 2 of ($x_3_*) and 8 of ($x_2_*) and 18 of ($x_1_*))) or
            ((2 of ($x_10_*) and 3 of ($x_3_*) and 1 of ($x_2_*) and 29 of ($x_1_*))) or
            ((2 of ($x_10_*) and 3 of ($x_3_*) and 2 of ($x_2_*) and 27 of ($x_1_*))) or
            ((2 of ($x_10_*) and 3 of ($x_3_*) and 3 of ($x_2_*) and 25 of ($x_1_*))) or
            ((2 of ($x_10_*) and 3 of ($x_3_*) and 4 of ($x_2_*) and 23 of ($x_1_*))) or
            ((2 of ($x_10_*) and 3 of ($x_3_*) and 5 of ($x_2_*) and 21 of ($x_1_*))) or
            ((2 of ($x_10_*) and 3 of ($x_3_*) and 6 of ($x_2_*) and 19 of ($x_1_*))) or
            ((2 of ($x_10_*) and 3 of ($x_3_*) and 7 of ($x_2_*) and 17 of ($x_1_*))) or
            ((2 of ($x_10_*) and 3 of ($x_3_*) and 8 of ($x_2_*) and 15 of ($x_1_*))) or
            ((2 of ($x_10_*) and 1 of ($x_4_*) and 3 of ($x_2_*) and 30 of ($x_1_*))) or
            ((2 of ($x_10_*) and 1 of ($x_4_*) and 4 of ($x_2_*) and 28 of ($x_1_*))) or
            ((2 of ($x_10_*) and 1 of ($x_4_*) and 5 of ($x_2_*) and 26 of ($x_1_*))) or
            ((2 of ($x_10_*) and 1 of ($x_4_*) and 6 of ($x_2_*) and 24 of ($x_1_*))) or
            ((2 of ($x_10_*) and 1 of ($x_4_*) and 7 of ($x_2_*) and 22 of ($x_1_*))) or
            ((2 of ($x_10_*) and 1 of ($x_4_*) and 8 of ($x_2_*) and 20 of ($x_1_*))) or
            ((2 of ($x_10_*) and 1 of ($x_4_*) and 1 of ($x_3_*) and 2 of ($x_2_*) and 29 of ($x_1_*))) or
            ((2 of ($x_10_*) and 1 of ($x_4_*) and 1 of ($x_3_*) and 3 of ($x_2_*) and 27 of ($x_1_*))) or
            ((2 of ($x_10_*) and 1 of ($x_4_*) and 1 of ($x_3_*) and 4 of ($x_2_*) and 25 of ($x_1_*))) or
            ((2 of ($x_10_*) and 1 of ($x_4_*) and 1 of ($x_3_*) and 5 of ($x_2_*) and 23 of ($x_1_*))) or
            ((2 of ($x_10_*) and 1 of ($x_4_*) and 1 of ($x_3_*) and 6 of ($x_2_*) and 21 of ($x_1_*))) or
            ((2 of ($x_10_*) and 1 of ($x_4_*) and 1 of ($x_3_*) and 7 of ($x_2_*) and 19 of ($x_1_*))) or
            ((2 of ($x_10_*) and 1 of ($x_4_*) and 1 of ($x_3_*) and 8 of ($x_2_*) and 17 of ($x_1_*))) or
            ((2 of ($x_10_*) and 1 of ($x_4_*) and 2 of ($x_3_*) and 30 of ($x_1_*))) or
            ((2 of ($x_10_*) and 1 of ($x_4_*) and 2 of ($x_3_*) and 1 of ($x_2_*) and 28 of ($x_1_*))) or
            ((2 of ($x_10_*) and 1 of ($x_4_*) and 2 of ($x_3_*) and 2 of ($x_2_*) and 26 of ($x_1_*))) or
            ((2 of ($x_10_*) and 1 of ($x_4_*) and 2 of ($x_3_*) and 3 of ($x_2_*) and 24 of ($x_1_*))) or
            ((2 of ($x_10_*) and 1 of ($x_4_*) and 2 of ($x_3_*) and 4 of ($x_2_*) and 22 of ($x_1_*))) or
            ((2 of ($x_10_*) and 1 of ($x_4_*) and 2 of ($x_3_*) and 5 of ($x_2_*) and 20 of ($x_1_*))) or
            ((2 of ($x_10_*) and 1 of ($x_4_*) and 2 of ($x_3_*) and 6 of ($x_2_*) and 18 of ($x_1_*))) or
            ((2 of ($x_10_*) and 1 of ($x_4_*) and 2 of ($x_3_*) and 7 of ($x_2_*) and 16 of ($x_1_*))) or
            ((2 of ($x_10_*) and 1 of ($x_4_*) and 2 of ($x_3_*) and 8 of ($x_2_*) and 14 of ($x_1_*))) or
            ((2 of ($x_10_*) and 1 of ($x_4_*) and 3 of ($x_3_*) and 27 of ($x_1_*))) or
            ((2 of ($x_10_*) and 1 of ($x_4_*) and 3 of ($x_3_*) and 1 of ($x_2_*) and 25 of ($x_1_*))) or
            ((2 of ($x_10_*) and 1 of ($x_4_*) and 3 of ($x_3_*) and 2 of ($x_2_*) and 23 of ($x_1_*))) or
            ((2 of ($x_10_*) and 1 of ($x_4_*) and 3 of ($x_3_*) and 3 of ($x_2_*) and 21 of ($x_1_*))) or
            ((2 of ($x_10_*) and 1 of ($x_4_*) and 3 of ($x_3_*) and 4 of ($x_2_*) and 19 of ($x_1_*))) or
            ((2 of ($x_10_*) and 1 of ($x_4_*) and 3 of ($x_3_*) and 5 of ($x_2_*) and 17 of ($x_1_*))) or
            ((2 of ($x_10_*) and 1 of ($x_4_*) and 3 of ($x_3_*) and 6 of ($x_2_*) and 15 of ($x_1_*))) or
            ((2 of ($x_10_*) and 1 of ($x_4_*) and 3 of ($x_3_*) and 7 of ($x_2_*) and 13 of ($x_1_*))) or
            ((2 of ($x_10_*) and 1 of ($x_4_*) and 3 of ($x_3_*) and 8 of ($x_2_*) and 11 of ($x_1_*))) or
            ((2 of ($x_10_*) and 1 of ($x_5_*) and 3 of ($x_2_*) and 29 of ($x_1_*))) or
            ((2 of ($x_10_*) and 1 of ($x_5_*) and 4 of ($x_2_*) and 27 of ($x_1_*))) or
            ((2 of ($x_10_*) and 1 of ($x_5_*) and 5 of ($x_2_*) and 25 of ($x_1_*))) or
            ((2 of ($x_10_*) and 1 of ($x_5_*) and 6 of ($x_2_*) and 23 of ($x_1_*))) or
            ((2 of ($x_10_*) and 1 of ($x_5_*) and 7 of ($x_2_*) and 21 of ($x_1_*))) or
            ((2 of ($x_10_*) and 1 of ($x_5_*) and 8 of ($x_2_*) and 19 of ($x_1_*))) or
            ((2 of ($x_10_*) and 1 of ($x_5_*) and 1 of ($x_3_*) and 1 of ($x_2_*) and 30 of ($x_1_*))) or
            ((2 of ($x_10_*) and 1 of ($x_5_*) and 1 of ($x_3_*) and 2 of ($x_2_*) and 28 of ($x_1_*))) or
            ((2 of ($x_10_*) and 1 of ($x_5_*) and 1 of ($x_3_*) and 3 of ($x_2_*) and 26 of ($x_1_*))) or
            ((2 of ($x_10_*) and 1 of ($x_5_*) and 1 of ($x_3_*) and 4 of ($x_2_*) and 24 of ($x_1_*))) or
            ((2 of ($x_10_*) and 1 of ($x_5_*) and 1 of ($x_3_*) and 5 of ($x_2_*) and 22 of ($x_1_*))) or
            ((2 of ($x_10_*) and 1 of ($x_5_*) and 1 of ($x_3_*) and 6 of ($x_2_*) and 20 of ($x_1_*))) or
            ((2 of ($x_10_*) and 1 of ($x_5_*) and 1 of ($x_3_*) and 7 of ($x_2_*) and 18 of ($x_1_*))) or
            ((2 of ($x_10_*) and 1 of ($x_5_*) and 1 of ($x_3_*) and 8 of ($x_2_*) and 16 of ($x_1_*))) or
            ((2 of ($x_10_*) and 1 of ($x_5_*) and 2 of ($x_3_*) and 29 of ($x_1_*))) or
            ((2 of ($x_10_*) and 1 of ($x_5_*) and 2 of ($x_3_*) and 1 of ($x_2_*) and 27 of ($x_1_*))) or
            ((2 of ($x_10_*) and 1 of ($x_5_*) and 2 of ($x_3_*) and 2 of ($x_2_*) and 25 of ($x_1_*))) or
            ((2 of ($x_10_*) and 1 of ($x_5_*) and 2 of ($x_3_*) and 3 of ($x_2_*) and 23 of ($x_1_*))) or
            ((2 of ($x_10_*) and 1 of ($x_5_*) and 2 of ($x_3_*) and 4 of ($x_2_*) and 21 of ($x_1_*))) or
            ((2 of ($x_10_*) and 1 of ($x_5_*) and 2 of ($x_3_*) and 5 of ($x_2_*) and 19 of ($x_1_*))) or
            ((2 of ($x_10_*) and 1 of ($x_5_*) and 2 of ($x_3_*) and 6 of ($x_2_*) and 17 of ($x_1_*))) or
            ((2 of ($x_10_*) and 1 of ($x_5_*) and 2 of ($x_3_*) and 7 of ($x_2_*) and 15 of ($x_1_*))) or
            ((2 of ($x_10_*) and 1 of ($x_5_*) and 2 of ($x_3_*) and 8 of ($x_2_*) and 13 of ($x_1_*))) or
            ((2 of ($x_10_*) and 1 of ($x_5_*) and 3 of ($x_3_*) and 26 of ($x_1_*))) or
            ((2 of ($x_10_*) and 1 of ($x_5_*) and 3 of ($x_3_*) and 1 of ($x_2_*) and 24 of ($x_1_*))) or
            ((2 of ($x_10_*) and 1 of ($x_5_*) and 3 of ($x_3_*) and 2 of ($x_2_*) and 22 of ($x_1_*))) or
            ((2 of ($x_10_*) and 1 of ($x_5_*) and 3 of ($x_3_*) and 3 of ($x_2_*) and 20 of ($x_1_*))) or
            ((2 of ($x_10_*) and 1 of ($x_5_*) and 3 of ($x_3_*) and 4 of ($x_2_*) and 18 of ($x_1_*))) or
            ((2 of ($x_10_*) and 1 of ($x_5_*) and 3 of ($x_3_*) and 5 of ($x_2_*) and 16 of ($x_1_*))) or
            ((2 of ($x_10_*) and 1 of ($x_5_*) and 3 of ($x_3_*) and 6 of ($x_2_*) and 14 of ($x_1_*))) or
            ((2 of ($x_10_*) and 1 of ($x_5_*) and 3 of ($x_3_*) and 7 of ($x_2_*) and 12 of ($x_1_*))) or
            ((2 of ($x_10_*) and 1 of ($x_5_*) and 3 of ($x_3_*) and 8 of ($x_2_*) and 10 of ($x_1_*))) or
            ((2 of ($x_10_*) and 1 of ($x_5_*) and 1 of ($x_4_*) and 1 of ($x_2_*) and 29 of ($x_1_*))) or
            ((2 of ($x_10_*) and 1 of ($x_5_*) and 1 of ($x_4_*) and 2 of ($x_2_*) and 27 of ($x_1_*))) or
            ((2 of ($x_10_*) and 1 of ($x_5_*) and 1 of ($x_4_*) and 3 of ($x_2_*) and 25 of ($x_1_*))) or
            ((2 of ($x_10_*) and 1 of ($x_5_*) and 1 of ($x_4_*) and 4 of ($x_2_*) and 23 of ($x_1_*))) or
            ((2 of ($x_10_*) and 1 of ($x_5_*) and 1 of ($x_4_*) and 5 of ($x_2_*) and 21 of ($x_1_*))) or
            ((2 of ($x_10_*) and 1 of ($x_5_*) and 1 of ($x_4_*) and 6 of ($x_2_*) and 19 of ($x_1_*))) or
            ((2 of ($x_10_*) and 1 of ($x_5_*) and 1 of ($x_4_*) and 7 of ($x_2_*) and 17 of ($x_1_*))) or
            ((2 of ($x_10_*) and 1 of ($x_5_*) and 1 of ($x_4_*) and 8 of ($x_2_*) and 15 of ($x_1_*))) or
            ((2 of ($x_10_*) and 1 of ($x_5_*) and 1 of ($x_4_*) and 1 of ($x_3_*) and 28 of ($x_1_*))) or
            ((2 of ($x_10_*) and 1 of ($x_5_*) and 1 of ($x_4_*) and 1 of ($x_3_*) and 1 of ($x_2_*) and 26 of ($x_1_*))) or
            ((2 of ($x_10_*) and 1 of ($x_5_*) and 1 of ($x_4_*) and 1 of ($x_3_*) and 2 of ($x_2_*) and 24 of ($x_1_*))) or
            ((2 of ($x_10_*) and 1 of ($x_5_*) and 1 of ($x_4_*) and 1 of ($x_3_*) and 3 of ($x_2_*) and 22 of ($x_1_*))) or
            ((2 of ($x_10_*) and 1 of ($x_5_*) and 1 of ($x_4_*) and 1 of ($x_3_*) and 4 of ($x_2_*) and 20 of ($x_1_*))) or
            ((2 of ($x_10_*) and 1 of ($x_5_*) and 1 of ($x_4_*) and 1 of ($x_3_*) and 5 of ($x_2_*) and 18 of ($x_1_*))) or
            ((2 of ($x_10_*) and 1 of ($x_5_*) and 1 of ($x_4_*) and 1 of ($x_3_*) and 6 of ($x_2_*) and 16 of ($x_1_*))) or
            ((2 of ($x_10_*) and 1 of ($x_5_*) and 1 of ($x_4_*) and 1 of ($x_3_*) and 7 of ($x_2_*) and 14 of ($x_1_*))) or
            ((2 of ($x_10_*) and 1 of ($x_5_*) and 1 of ($x_4_*) and 1 of ($x_3_*) and 8 of ($x_2_*) and 12 of ($x_1_*))) or
            ((2 of ($x_10_*) and 1 of ($x_5_*) and 1 of ($x_4_*) and 2 of ($x_3_*) and 25 of ($x_1_*))) or
            ((2 of ($x_10_*) and 1 of ($x_5_*) and 1 of ($x_4_*) and 2 of ($x_3_*) and 1 of ($x_2_*) and 23 of ($x_1_*))) or
            ((2 of ($x_10_*) and 1 of ($x_5_*) and 1 of ($x_4_*) and 2 of ($x_3_*) and 2 of ($x_2_*) and 21 of ($x_1_*))) or
            ((2 of ($x_10_*) and 1 of ($x_5_*) and 1 of ($x_4_*) and 2 of ($x_3_*) and 3 of ($x_2_*) and 19 of ($x_1_*))) or
            ((2 of ($x_10_*) and 1 of ($x_5_*) and 1 of ($x_4_*) and 2 of ($x_3_*) and 4 of ($x_2_*) and 17 of ($x_1_*))) or
            ((2 of ($x_10_*) and 1 of ($x_5_*) and 1 of ($x_4_*) and 2 of ($x_3_*) and 5 of ($x_2_*) and 15 of ($x_1_*))) or
            ((2 of ($x_10_*) and 1 of ($x_5_*) and 1 of ($x_4_*) and 2 of ($x_3_*) and 6 of ($x_2_*) and 13 of ($x_1_*))) or
            ((2 of ($x_10_*) and 1 of ($x_5_*) and 1 of ($x_4_*) and 2 of ($x_3_*) and 7 of ($x_2_*) and 11 of ($x_1_*))) or
            ((2 of ($x_10_*) and 1 of ($x_5_*) and 1 of ($x_4_*) and 2 of ($x_3_*) and 8 of ($x_2_*) and 9 of ($x_1_*))) or
            ((2 of ($x_10_*) and 1 of ($x_5_*) and 1 of ($x_4_*) and 3 of ($x_3_*) and 22 of ($x_1_*))) or
            ((2 of ($x_10_*) and 1 of ($x_5_*) and 1 of ($x_4_*) and 3 of ($x_3_*) and 1 of ($x_2_*) and 20 of ($x_1_*))) or
            ((2 of ($x_10_*) and 1 of ($x_5_*) and 1 of ($x_4_*) and 3 of ($x_3_*) and 2 of ($x_2_*) and 18 of ($x_1_*))) or
            ((2 of ($x_10_*) and 1 of ($x_5_*) and 1 of ($x_4_*) and 3 of ($x_3_*) and 3 of ($x_2_*) and 16 of ($x_1_*))) or
            ((2 of ($x_10_*) and 1 of ($x_5_*) and 1 of ($x_4_*) and 3 of ($x_3_*) and 4 of ($x_2_*) and 14 of ($x_1_*))) or
            ((2 of ($x_10_*) and 1 of ($x_5_*) and 1 of ($x_4_*) and 3 of ($x_3_*) and 5 of ($x_2_*) and 12 of ($x_1_*))) or
            ((2 of ($x_10_*) and 1 of ($x_5_*) and 1 of ($x_4_*) and 3 of ($x_3_*) and 6 of ($x_2_*) and 10 of ($x_1_*))) or
            ((2 of ($x_10_*) and 1 of ($x_5_*) and 1 of ($x_4_*) and 3 of ($x_3_*) and 7 of ($x_2_*) and 8 of ($x_1_*))) or
            ((2 of ($x_10_*) and 1 of ($x_5_*) and 1 of ($x_4_*) and 3 of ($x_3_*) and 8 of ($x_2_*) and 6 of ($x_1_*))) or
            ((2 of ($x_10_*) and 2 of ($x_5_*) and 30 of ($x_1_*))) or
            ((2 of ($x_10_*) and 2 of ($x_5_*) and 1 of ($x_2_*) and 28 of ($x_1_*))) or
            ((2 of ($x_10_*) and 2 of ($x_5_*) and 2 of ($x_2_*) and 26 of ($x_1_*))) or
            ((2 of ($x_10_*) and 2 of ($x_5_*) and 3 of ($x_2_*) and 24 of ($x_1_*))) or
            ((2 of ($x_10_*) and 2 of ($x_5_*) and 4 of ($x_2_*) and 22 of ($x_1_*))) or
            ((2 of ($x_10_*) and 2 of ($x_5_*) and 5 of ($x_2_*) and 20 of ($x_1_*))) or
            ((2 of ($x_10_*) and 2 of ($x_5_*) and 6 of ($x_2_*) and 18 of ($x_1_*))) or
            ((2 of ($x_10_*) and 2 of ($x_5_*) and 7 of ($x_2_*) and 16 of ($x_1_*))) or
            ((2 of ($x_10_*) and 2 of ($x_5_*) and 8 of ($x_2_*) and 14 of ($x_1_*))) or
            ((2 of ($x_10_*) and 2 of ($x_5_*) and 1 of ($x_3_*) and 27 of ($x_1_*))) or
            ((2 of ($x_10_*) and 2 of ($x_5_*) and 1 of ($x_3_*) and 1 of ($x_2_*) and 25 of ($x_1_*))) or
            ((2 of ($x_10_*) and 2 of ($x_5_*) and 1 of ($x_3_*) and 2 of ($x_2_*) and 23 of ($x_1_*))) or
            ((2 of ($x_10_*) and 2 of ($x_5_*) and 1 of ($x_3_*) and 3 of ($x_2_*) and 21 of ($x_1_*))) or
            ((2 of ($x_10_*) and 2 of ($x_5_*) and 1 of ($x_3_*) and 4 of ($x_2_*) and 19 of ($x_1_*))) or
            ((2 of ($x_10_*) and 2 of ($x_5_*) and 1 of ($x_3_*) and 5 of ($x_2_*) and 17 of ($x_1_*))) or
            ((2 of ($x_10_*) and 2 of ($x_5_*) and 1 of ($x_3_*) and 6 of ($x_2_*) and 15 of ($x_1_*))) or
            ((2 of ($x_10_*) and 2 of ($x_5_*) and 1 of ($x_3_*) and 7 of ($x_2_*) and 13 of ($x_1_*))) or
            ((2 of ($x_10_*) and 2 of ($x_5_*) and 1 of ($x_3_*) and 8 of ($x_2_*) and 11 of ($x_1_*))) or
            ((2 of ($x_10_*) and 2 of ($x_5_*) and 2 of ($x_3_*) and 24 of ($x_1_*))) or
            ((2 of ($x_10_*) and 2 of ($x_5_*) and 2 of ($x_3_*) and 1 of ($x_2_*) and 22 of ($x_1_*))) or
            ((2 of ($x_10_*) and 2 of ($x_5_*) and 2 of ($x_3_*) and 2 of ($x_2_*) and 20 of ($x_1_*))) or
            ((2 of ($x_10_*) and 2 of ($x_5_*) and 2 of ($x_3_*) and 3 of ($x_2_*) and 18 of ($x_1_*))) or
            ((2 of ($x_10_*) and 2 of ($x_5_*) and 2 of ($x_3_*) and 4 of ($x_2_*) and 16 of ($x_1_*))) or
            ((2 of ($x_10_*) and 2 of ($x_5_*) and 2 of ($x_3_*) and 5 of ($x_2_*) and 14 of ($x_1_*))) or
            ((2 of ($x_10_*) and 2 of ($x_5_*) and 2 of ($x_3_*) and 6 of ($x_2_*) and 12 of ($x_1_*))) or
            ((2 of ($x_10_*) and 2 of ($x_5_*) and 2 of ($x_3_*) and 7 of ($x_2_*) and 10 of ($x_1_*))) or
            ((2 of ($x_10_*) and 2 of ($x_5_*) and 2 of ($x_3_*) and 8 of ($x_2_*) and 8 of ($x_1_*))) or
            ((2 of ($x_10_*) and 2 of ($x_5_*) and 3 of ($x_3_*) and 21 of ($x_1_*))) or
            ((2 of ($x_10_*) and 2 of ($x_5_*) and 3 of ($x_3_*) and 1 of ($x_2_*) and 19 of ($x_1_*))) or
            ((2 of ($x_10_*) and 2 of ($x_5_*) and 3 of ($x_3_*) and 2 of ($x_2_*) and 17 of ($x_1_*))) or
            ((2 of ($x_10_*) and 2 of ($x_5_*) and 3 of ($x_3_*) and 3 of ($x_2_*) and 15 of ($x_1_*))) or
            ((2 of ($x_10_*) and 2 of ($x_5_*) and 3 of ($x_3_*) and 4 of ($x_2_*) and 13 of ($x_1_*))) or
            ((2 of ($x_10_*) and 2 of ($x_5_*) and 3 of ($x_3_*) and 5 of ($x_2_*) and 11 of ($x_1_*))) or
            ((2 of ($x_10_*) and 2 of ($x_5_*) and 3 of ($x_3_*) and 6 of ($x_2_*) and 9 of ($x_1_*))) or
            ((2 of ($x_10_*) and 2 of ($x_5_*) and 3 of ($x_3_*) and 7 of ($x_2_*) and 7 of ($x_1_*))) or
            ((2 of ($x_10_*) and 2 of ($x_5_*) and 3 of ($x_3_*) and 8 of ($x_2_*) and 5 of ($x_1_*))) or
            ((2 of ($x_10_*) and 2 of ($x_5_*) and 1 of ($x_4_*) and 26 of ($x_1_*))) or
            ((2 of ($x_10_*) and 2 of ($x_5_*) and 1 of ($x_4_*) and 1 of ($x_2_*) and 24 of ($x_1_*))) or
            ((2 of ($x_10_*) and 2 of ($x_5_*) and 1 of ($x_4_*) and 2 of ($x_2_*) and 22 of ($x_1_*))) or
            ((2 of ($x_10_*) and 2 of ($x_5_*) and 1 of ($x_4_*) and 3 of ($x_2_*) and 20 of ($x_1_*))) or
            ((2 of ($x_10_*) and 2 of ($x_5_*) and 1 of ($x_4_*) and 4 of ($x_2_*) and 18 of ($x_1_*))) or
            ((2 of ($x_10_*) and 2 of ($x_5_*) and 1 of ($x_4_*) and 5 of ($x_2_*) and 16 of ($x_1_*))) or
            ((2 of ($x_10_*) and 2 of ($x_5_*) and 1 of ($x_4_*) and 6 of ($x_2_*) and 14 of ($x_1_*))) or
            ((2 of ($x_10_*) and 2 of ($x_5_*) and 1 of ($x_4_*) and 7 of ($x_2_*) and 12 of ($x_1_*))) or
            ((2 of ($x_10_*) and 2 of ($x_5_*) and 1 of ($x_4_*) and 8 of ($x_2_*) and 10 of ($x_1_*))) or
            ((2 of ($x_10_*) and 2 of ($x_5_*) and 1 of ($x_4_*) and 1 of ($x_3_*) and 23 of ($x_1_*))) or
            ((2 of ($x_10_*) and 2 of ($x_5_*) and 1 of ($x_4_*) and 1 of ($x_3_*) and 1 of ($x_2_*) and 21 of ($x_1_*))) or
            ((2 of ($x_10_*) and 2 of ($x_5_*) and 1 of ($x_4_*) and 1 of ($x_3_*) and 2 of ($x_2_*) and 19 of ($x_1_*))) or
            ((2 of ($x_10_*) and 2 of ($x_5_*) and 1 of ($x_4_*) and 1 of ($x_3_*) and 3 of ($x_2_*) and 17 of ($x_1_*))) or
            ((2 of ($x_10_*) and 2 of ($x_5_*) and 1 of ($x_4_*) and 1 of ($x_3_*) and 4 of ($x_2_*) and 15 of ($x_1_*))) or
            ((2 of ($x_10_*) and 2 of ($x_5_*) and 1 of ($x_4_*) and 1 of ($x_3_*) and 5 of ($x_2_*) and 13 of ($x_1_*))) or
            ((2 of ($x_10_*) and 2 of ($x_5_*) and 1 of ($x_4_*) and 1 of ($x_3_*) and 6 of ($x_2_*) and 11 of ($x_1_*))) or
            ((2 of ($x_10_*) and 2 of ($x_5_*) and 1 of ($x_4_*) and 1 of ($x_3_*) and 7 of ($x_2_*) and 9 of ($x_1_*))) or
            ((2 of ($x_10_*) and 2 of ($x_5_*) and 1 of ($x_4_*) and 1 of ($x_3_*) and 8 of ($x_2_*) and 7 of ($x_1_*))) or
            ((2 of ($x_10_*) and 2 of ($x_5_*) and 1 of ($x_4_*) and 2 of ($x_3_*) and 20 of ($x_1_*))) or
            ((2 of ($x_10_*) and 2 of ($x_5_*) and 1 of ($x_4_*) and 2 of ($x_3_*) and 1 of ($x_2_*) and 18 of ($x_1_*))) or
            ((2 of ($x_10_*) and 2 of ($x_5_*) and 1 of ($x_4_*) and 2 of ($x_3_*) and 2 of ($x_2_*) and 16 of ($x_1_*))) or
            ((2 of ($x_10_*) and 2 of ($x_5_*) and 1 of ($x_4_*) and 2 of ($x_3_*) and 3 of ($x_2_*) and 14 of ($x_1_*))) or
            ((2 of ($x_10_*) and 2 of ($x_5_*) and 1 of ($x_4_*) and 2 of ($x_3_*) and 4 of ($x_2_*) and 12 of ($x_1_*))) or
            ((2 of ($x_10_*) and 2 of ($x_5_*) and 1 of ($x_4_*) and 2 of ($x_3_*) and 5 of ($x_2_*) and 10 of ($x_1_*))) or
            ((2 of ($x_10_*) and 2 of ($x_5_*) and 1 of ($x_4_*) and 2 of ($x_3_*) and 6 of ($x_2_*) and 8 of ($x_1_*))) or
            ((2 of ($x_10_*) and 2 of ($x_5_*) and 1 of ($x_4_*) and 2 of ($x_3_*) and 7 of ($x_2_*) and 6 of ($x_1_*))) or
            ((2 of ($x_10_*) and 2 of ($x_5_*) and 1 of ($x_4_*) and 2 of ($x_3_*) and 8 of ($x_2_*) and 4 of ($x_1_*))) or
            ((2 of ($x_10_*) and 2 of ($x_5_*) and 1 of ($x_4_*) and 3 of ($x_3_*) and 17 of ($x_1_*))) or
            ((2 of ($x_10_*) and 2 of ($x_5_*) and 1 of ($x_4_*) and 3 of ($x_3_*) and 1 of ($x_2_*) and 15 of ($x_1_*))) or
            ((2 of ($x_10_*) and 2 of ($x_5_*) and 1 of ($x_4_*) and 3 of ($x_3_*) and 2 of ($x_2_*) and 13 of ($x_1_*))) or
            ((2 of ($x_10_*) and 2 of ($x_5_*) and 1 of ($x_4_*) and 3 of ($x_3_*) and 3 of ($x_2_*) and 11 of ($x_1_*))) or
            ((2 of ($x_10_*) and 2 of ($x_5_*) and 1 of ($x_4_*) and 3 of ($x_3_*) and 4 of ($x_2_*) and 9 of ($x_1_*))) or
            ((2 of ($x_10_*) and 2 of ($x_5_*) and 1 of ($x_4_*) and 3 of ($x_3_*) and 5 of ($x_2_*) and 7 of ($x_1_*))) or
            ((2 of ($x_10_*) and 2 of ($x_5_*) and 1 of ($x_4_*) and 3 of ($x_3_*) and 6 of ($x_2_*) and 5 of ($x_1_*))) or
            ((2 of ($x_10_*) and 2 of ($x_5_*) and 1 of ($x_4_*) and 3 of ($x_3_*) and 7 of ($x_2_*) and 3 of ($x_1_*))) or
            ((2 of ($x_10_*) and 2 of ($x_5_*) and 1 of ($x_4_*) and 3 of ($x_3_*) and 8 of ($x_2_*) and 1 of ($x_1_*))) or
            ((2 of ($x_10_*) and 3 of ($x_5_*) and 25 of ($x_1_*))) or
            ((2 of ($x_10_*) and 3 of ($x_5_*) and 1 of ($x_2_*) and 23 of ($x_1_*))) or
            ((2 of ($x_10_*) and 3 of ($x_5_*) and 2 of ($x_2_*) and 21 of ($x_1_*))) or
            ((2 of ($x_10_*) and 3 of ($x_5_*) and 3 of ($x_2_*) and 19 of ($x_1_*))) or
            ((2 of ($x_10_*) and 3 of ($x_5_*) and 4 of ($x_2_*) and 17 of ($x_1_*))) or
            ((2 of ($x_10_*) and 3 of ($x_5_*) and 5 of ($x_2_*) and 15 of ($x_1_*))) or
            ((2 of ($x_10_*) and 3 of ($x_5_*) and 6 of ($x_2_*) and 13 of ($x_1_*))) or
            ((2 of ($x_10_*) and 3 of ($x_5_*) and 7 of ($x_2_*) and 11 of ($x_1_*))) or
            ((2 of ($x_10_*) and 3 of ($x_5_*) and 8 of ($x_2_*) and 9 of ($x_1_*))) or
            ((2 of ($x_10_*) and 3 of ($x_5_*) and 1 of ($x_3_*) and 22 of ($x_1_*))) or
            ((2 of ($x_10_*) and 3 of ($x_5_*) and 1 of ($x_3_*) and 1 of ($x_2_*) and 20 of ($x_1_*))) or
            ((2 of ($x_10_*) and 3 of ($x_5_*) and 1 of ($x_3_*) and 2 of ($x_2_*) and 18 of ($x_1_*))) or
            ((2 of ($x_10_*) and 3 of ($x_5_*) and 1 of ($x_3_*) and 3 of ($x_2_*) and 16 of ($x_1_*))) or
            ((2 of ($x_10_*) and 3 of ($x_5_*) and 1 of ($x_3_*) and 4 of ($x_2_*) and 14 of ($x_1_*))) or
            ((2 of ($x_10_*) and 3 of ($x_5_*) and 1 of ($x_3_*) and 5 of ($x_2_*) and 12 of ($x_1_*))) or
            ((2 of ($x_10_*) and 3 of ($x_5_*) and 1 of ($x_3_*) and 6 of ($x_2_*) and 10 of ($x_1_*))) or
            ((2 of ($x_10_*) and 3 of ($x_5_*) and 1 of ($x_3_*) and 7 of ($x_2_*) and 8 of ($x_1_*))) or
            ((2 of ($x_10_*) and 3 of ($x_5_*) and 1 of ($x_3_*) and 8 of ($x_2_*) and 6 of ($x_1_*))) or
            ((2 of ($x_10_*) and 3 of ($x_5_*) and 2 of ($x_3_*) and 19 of ($x_1_*))) or
            ((2 of ($x_10_*) and 3 of ($x_5_*) and 2 of ($x_3_*) and 1 of ($x_2_*) and 17 of ($x_1_*))) or
            ((2 of ($x_10_*) and 3 of ($x_5_*) and 2 of ($x_3_*) and 2 of ($x_2_*) and 15 of ($x_1_*))) or
            ((2 of ($x_10_*) and 3 of ($x_5_*) and 2 of ($x_3_*) and 3 of ($x_2_*) and 13 of ($x_1_*))) or
            ((2 of ($x_10_*) and 3 of ($x_5_*) and 2 of ($x_3_*) and 4 of ($x_2_*) and 11 of ($x_1_*))) or
            ((2 of ($x_10_*) and 3 of ($x_5_*) and 2 of ($x_3_*) and 5 of ($x_2_*) and 9 of ($x_1_*))) or
            ((2 of ($x_10_*) and 3 of ($x_5_*) and 2 of ($x_3_*) and 6 of ($x_2_*) and 7 of ($x_1_*))) or
            ((2 of ($x_10_*) and 3 of ($x_5_*) and 2 of ($x_3_*) and 7 of ($x_2_*) and 5 of ($x_1_*))) or
            ((2 of ($x_10_*) and 3 of ($x_5_*) and 2 of ($x_3_*) and 8 of ($x_2_*) and 3 of ($x_1_*))) or
            ((2 of ($x_10_*) and 3 of ($x_5_*) and 3 of ($x_3_*) and 16 of ($x_1_*))) or
            ((2 of ($x_10_*) and 3 of ($x_5_*) and 3 of ($x_3_*) and 1 of ($x_2_*) and 14 of ($x_1_*))) or
            ((2 of ($x_10_*) and 3 of ($x_5_*) and 3 of ($x_3_*) and 2 of ($x_2_*) and 12 of ($x_1_*))) or
            ((2 of ($x_10_*) and 3 of ($x_5_*) and 3 of ($x_3_*) and 3 of ($x_2_*) and 10 of ($x_1_*))) or
            ((2 of ($x_10_*) and 3 of ($x_5_*) and 3 of ($x_3_*) and 4 of ($x_2_*) and 8 of ($x_1_*))) or
            ((2 of ($x_10_*) and 3 of ($x_5_*) and 3 of ($x_3_*) and 5 of ($x_2_*) and 6 of ($x_1_*))) or
            ((2 of ($x_10_*) and 3 of ($x_5_*) and 3 of ($x_3_*) and 6 of ($x_2_*) and 4 of ($x_1_*))) or
            ((2 of ($x_10_*) and 3 of ($x_5_*) and 3 of ($x_3_*) and 7 of ($x_2_*) and 2 of ($x_1_*))) or
            ((2 of ($x_10_*) and 3 of ($x_5_*) and 3 of ($x_3_*) and 8 of ($x_2_*))) or
            ((2 of ($x_10_*) and 3 of ($x_5_*) and 1 of ($x_4_*) and 21 of ($x_1_*))) or
            ((2 of ($x_10_*) and 3 of ($x_5_*) and 1 of ($x_4_*) and 1 of ($x_2_*) and 19 of ($x_1_*))) or
            ((2 of ($x_10_*) and 3 of ($x_5_*) and 1 of ($x_4_*) and 2 of ($x_2_*) and 17 of ($x_1_*))) or
            ((2 of ($x_10_*) and 3 of ($x_5_*) and 1 of ($x_4_*) and 3 of ($x_2_*) and 15 of ($x_1_*))) or
            ((2 of ($x_10_*) and 3 of ($x_5_*) and 1 of ($x_4_*) and 4 of ($x_2_*) and 13 of ($x_1_*))) or
            ((2 of ($x_10_*) and 3 of ($x_5_*) and 1 of ($x_4_*) and 5 of ($x_2_*) and 11 of ($x_1_*))) or
            ((2 of ($x_10_*) and 3 of ($x_5_*) and 1 of ($x_4_*) and 6 of ($x_2_*) and 9 of ($x_1_*))) or
            ((2 of ($x_10_*) and 3 of ($x_5_*) and 1 of ($x_4_*) and 7 of ($x_2_*) and 7 of ($x_1_*))) or
            ((2 of ($x_10_*) and 3 of ($x_5_*) and 1 of ($x_4_*) and 8 of ($x_2_*) and 5 of ($x_1_*))) or
            ((2 of ($x_10_*) and 3 of ($x_5_*) and 1 of ($x_4_*) and 1 of ($x_3_*) and 18 of ($x_1_*))) or
            ((2 of ($x_10_*) and 3 of ($x_5_*) and 1 of ($x_4_*) and 1 of ($x_3_*) and 1 of ($x_2_*) and 16 of ($x_1_*))) or
            ((2 of ($x_10_*) and 3 of ($x_5_*) and 1 of ($x_4_*) and 1 of ($x_3_*) and 2 of ($x_2_*) and 14 of ($x_1_*))) or
            ((2 of ($x_10_*) and 3 of ($x_5_*) and 1 of ($x_4_*) and 1 of ($x_3_*) and 3 of ($x_2_*) and 12 of ($x_1_*))) or
            ((2 of ($x_10_*) and 3 of ($x_5_*) and 1 of ($x_4_*) and 1 of ($x_3_*) and 4 of ($x_2_*) and 10 of ($x_1_*))) or
            ((2 of ($x_10_*) and 3 of ($x_5_*) and 1 of ($x_4_*) and 1 of ($x_3_*) and 5 of ($x_2_*) and 8 of ($x_1_*))) or
            ((2 of ($x_10_*) and 3 of ($x_5_*) and 1 of ($x_4_*) and 1 of ($x_3_*) and 6 of ($x_2_*) and 6 of ($x_1_*))) or
            ((2 of ($x_10_*) and 3 of ($x_5_*) and 1 of ($x_4_*) and 1 of ($x_3_*) and 7 of ($x_2_*) and 4 of ($x_1_*))) or
            ((2 of ($x_10_*) and 3 of ($x_5_*) and 1 of ($x_4_*) and 1 of ($x_3_*) and 8 of ($x_2_*) and 2 of ($x_1_*))) or
            ((2 of ($x_10_*) and 3 of ($x_5_*) and 1 of ($x_4_*) and 2 of ($x_3_*) and 15 of ($x_1_*))) or
            ((2 of ($x_10_*) and 3 of ($x_5_*) and 1 of ($x_4_*) and 2 of ($x_3_*) and 1 of ($x_2_*) and 13 of ($x_1_*))) or
            ((2 of ($x_10_*) and 3 of ($x_5_*) and 1 of ($x_4_*) and 2 of ($x_3_*) and 2 of ($x_2_*) and 11 of ($x_1_*))) or
            ((2 of ($x_10_*) and 3 of ($x_5_*) and 1 of ($x_4_*) and 2 of ($x_3_*) and 3 of ($x_2_*) and 9 of ($x_1_*))) or
            ((2 of ($x_10_*) and 3 of ($x_5_*) and 1 of ($x_4_*) and 2 of ($x_3_*) and 4 of ($x_2_*) and 7 of ($x_1_*))) or
            ((2 of ($x_10_*) and 3 of ($x_5_*) and 1 of ($x_4_*) and 2 of ($x_3_*) and 5 of ($x_2_*) and 5 of ($x_1_*))) or
            ((2 of ($x_10_*) and 3 of ($x_5_*) and 1 of ($x_4_*) and 2 of ($x_3_*) and 6 of ($x_2_*) and 3 of ($x_1_*))) or
            ((2 of ($x_10_*) and 3 of ($x_5_*) and 1 of ($x_4_*) and 2 of ($x_3_*) and 7 of ($x_2_*) and 1 of ($x_1_*))) or
            ((2 of ($x_10_*) and 3 of ($x_5_*) and 1 of ($x_4_*) and 2 of ($x_3_*) and 8 of ($x_2_*))) or
            ((2 of ($x_10_*) and 3 of ($x_5_*) and 1 of ($x_4_*) and 3 of ($x_3_*) and 12 of ($x_1_*))) or
            ((2 of ($x_10_*) and 3 of ($x_5_*) and 1 of ($x_4_*) and 3 of ($x_3_*) and 1 of ($x_2_*) and 10 of ($x_1_*))) or
            ((2 of ($x_10_*) and 3 of ($x_5_*) and 1 of ($x_4_*) and 3 of ($x_3_*) and 2 of ($x_2_*) and 8 of ($x_1_*))) or
            ((2 of ($x_10_*) and 3 of ($x_5_*) and 1 of ($x_4_*) and 3 of ($x_3_*) and 3 of ($x_2_*) and 6 of ($x_1_*))) or
            ((2 of ($x_10_*) and 3 of ($x_5_*) and 1 of ($x_4_*) and 3 of ($x_3_*) and 4 of ($x_2_*) and 4 of ($x_1_*))) or
            ((2 of ($x_10_*) and 3 of ($x_5_*) and 1 of ($x_4_*) and 3 of ($x_3_*) and 5 of ($x_2_*) and 2 of ($x_1_*))) or
            ((2 of ($x_10_*) and 3 of ($x_5_*) and 1 of ($x_4_*) and 3 of ($x_3_*) and 6 of ($x_2_*))) or
            ((3 of ($x_10_*) and 30 of ($x_1_*))) or
            ((3 of ($x_10_*) and 1 of ($x_2_*) and 28 of ($x_1_*))) or
            ((3 of ($x_10_*) and 2 of ($x_2_*) and 26 of ($x_1_*))) or
            ((3 of ($x_10_*) and 3 of ($x_2_*) and 24 of ($x_1_*))) or
            ((3 of ($x_10_*) and 4 of ($x_2_*) and 22 of ($x_1_*))) or
            ((3 of ($x_10_*) and 5 of ($x_2_*) and 20 of ($x_1_*))) or
            ((3 of ($x_10_*) and 6 of ($x_2_*) and 18 of ($x_1_*))) or
            ((3 of ($x_10_*) and 7 of ($x_2_*) and 16 of ($x_1_*))) or
            ((3 of ($x_10_*) and 8 of ($x_2_*) and 14 of ($x_1_*))) or
            ((3 of ($x_10_*) and 1 of ($x_3_*) and 27 of ($x_1_*))) or
            ((3 of ($x_10_*) and 1 of ($x_3_*) and 1 of ($x_2_*) and 25 of ($x_1_*))) or
            ((3 of ($x_10_*) and 1 of ($x_3_*) and 2 of ($x_2_*) and 23 of ($x_1_*))) or
            ((3 of ($x_10_*) and 1 of ($x_3_*) and 3 of ($x_2_*) and 21 of ($x_1_*))) or
            ((3 of ($x_10_*) and 1 of ($x_3_*) and 4 of ($x_2_*) and 19 of ($x_1_*))) or
            ((3 of ($x_10_*) and 1 of ($x_3_*) and 5 of ($x_2_*) and 17 of ($x_1_*))) or
            ((3 of ($x_10_*) and 1 of ($x_3_*) and 6 of ($x_2_*) and 15 of ($x_1_*))) or
            ((3 of ($x_10_*) and 1 of ($x_3_*) and 7 of ($x_2_*) and 13 of ($x_1_*))) or
            ((3 of ($x_10_*) and 1 of ($x_3_*) and 8 of ($x_2_*) and 11 of ($x_1_*))) or
            ((3 of ($x_10_*) and 2 of ($x_3_*) and 24 of ($x_1_*))) or
            ((3 of ($x_10_*) and 2 of ($x_3_*) and 1 of ($x_2_*) and 22 of ($x_1_*))) or
            ((3 of ($x_10_*) and 2 of ($x_3_*) and 2 of ($x_2_*) and 20 of ($x_1_*))) or
            ((3 of ($x_10_*) and 2 of ($x_3_*) and 3 of ($x_2_*) and 18 of ($x_1_*))) or
            ((3 of ($x_10_*) and 2 of ($x_3_*) and 4 of ($x_2_*) and 16 of ($x_1_*))) or
            ((3 of ($x_10_*) and 2 of ($x_3_*) and 5 of ($x_2_*) and 14 of ($x_1_*))) or
            ((3 of ($x_10_*) and 2 of ($x_3_*) and 6 of ($x_2_*) and 12 of ($x_1_*))) or
            ((3 of ($x_10_*) and 2 of ($x_3_*) and 7 of ($x_2_*) and 10 of ($x_1_*))) or
            ((3 of ($x_10_*) and 2 of ($x_3_*) and 8 of ($x_2_*) and 8 of ($x_1_*))) or
            ((3 of ($x_10_*) and 3 of ($x_3_*) and 21 of ($x_1_*))) or
            ((3 of ($x_10_*) and 3 of ($x_3_*) and 1 of ($x_2_*) and 19 of ($x_1_*))) or
            ((3 of ($x_10_*) and 3 of ($x_3_*) and 2 of ($x_2_*) and 17 of ($x_1_*))) or
            ((3 of ($x_10_*) and 3 of ($x_3_*) and 3 of ($x_2_*) and 15 of ($x_1_*))) or
            ((3 of ($x_10_*) and 3 of ($x_3_*) and 4 of ($x_2_*) and 13 of ($x_1_*))) or
            ((3 of ($x_10_*) and 3 of ($x_3_*) and 5 of ($x_2_*) and 11 of ($x_1_*))) or
            ((3 of ($x_10_*) and 3 of ($x_3_*) and 6 of ($x_2_*) and 9 of ($x_1_*))) or
            ((3 of ($x_10_*) and 3 of ($x_3_*) and 7 of ($x_2_*) and 7 of ($x_1_*))) or
            ((3 of ($x_10_*) and 3 of ($x_3_*) and 8 of ($x_2_*) and 5 of ($x_1_*))) or
            ((3 of ($x_10_*) and 1 of ($x_4_*) and 26 of ($x_1_*))) or
            ((3 of ($x_10_*) and 1 of ($x_4_*) and 1 of ($x_2_*) and 24 of ($x_1_*))) or
            ((3 of ($x_10_*) and 1 of ($x_4_*) and 2 of ($x_2_*) and 22 of ($x_1_*))) or
            ((3 of ($x_10_*) and 1 of ($x_4_*) and 3 of ($x_2_*) and 20 of ($x_1_*))) or
            ((3 of ($x_10_*) and 1 of ($x_4_*) and 4 of ($x_2_*) and 18 of ($x_1_*))) or
            ((3 of ($x_10_*) and 1 of ($x_4_*) and 5 of ($x_2_*) and 16 of ($x_1_*))) or
            ((3 of ($x_10_*) and 1 of ($x_4_*) and 6 of ($x_2_*) and 14 of ($x_1_*))) or
            ((3 of ($x_10_*) and 1 of ($x_4_*) and 7 of ($x_2_*) and 12 of ($x_1_*))) or
            ((3 of ($x_10_*) and 1 of ($x_4_*) and 8 of ($x_2_*) and 10 of ($x_1_*))) or
            ((3 of ($x_10_*) and 1 of ($x_4_*) and 1 of ($x_3_*) and 23 of ($x_1_*))) or
            ((3 of ($x_10_*) and 1 of ($x_4_*) and 1 of ($x_3_*) and 1 of ($x_2_*) and 21 of ($x_1_*))) or
            ((3 of ($x_10_*) and 1 of ($x_4_*) and 1 of ($x_3_*) and 2 of ($x_2_*) and 19 of ($x_1_*))) or
            ((3 of ($x_10_*) and 1 of ($x_4_*) and 1 of ($x_3_*) and 3 of ($x_2_*) and 17 of ($x_1_*))) or
            ((3 of ($x_10_*) and 1 of ($x_4_*) and 1 of ($x_3_*) and 4 of ($x_2_*) and 15 of ($x_1_*))) or
            ((3 of ($x_10_*) and 1 of ($x_4_*) and 1 of ($x_3_*) and 5 of ($x_2_*) and 13 of ($x_1_*))) or
            ((3 of ($x_10_*) and 1 of ($x_4_*) and 1 of ($x_3_*) and 6 of ($x_2_*) and 11 of ($x_1_*))) or
            ((3 of ($x_10_*) and 1 of ($x_4_*) and 1 of ($x_3_*) and 7 of ($x_2_*) and 9 of ($x_1_*))) or
            ((3 of ($x_10_*) and 1 of ($x_4_*) and 1 of ($x_3_*) and 8 of ($x_2_*) and 7 of ($x_1_*))) or
            ((3 of ($x_10_*) and 1 of ($x_4_*) and 2 of ($x_3_*) and 20 of ($x_1_*))) or
            ((3 of ($x_10_*) and 1 of ($x_4_*) and 2 of ($x_3_*) and 1 of ($x_2_*) and 18 of ($x_1_*))) or
            ((3 of ($x_10_*) and 1 of ($x_4_*) and 2 of ($x_3_*) and 2 of ($x_2_*) and 16 of ($x_1_*))) or
            ((3 of ($x_10_*) and 1 of ($x_4_*) and 2 of ($x_3_*) and 3 of ($x_2_*) and 14 of ($x_1_*))) or
            ((3 of ($x_10_*) and 1 of ($x_4_*) and 2 of ($x_3_*) and 4 of ($x_2_*) and 12 of ($x_1_*))) or
            ((3 of ($x_10_*) and 1 of ($x_4_*) and 2 of ($x_3_*) and 5 of ($x_2_*) and 10 of ($x_1_*))) or
            ((3 of ($x_10_*) and 1 of ($x_4_*) and 2 of ($x_3_*) and 6 of ($x_2_*) and 8 of ($x_1_*))) or
            ((3 of ($x_10_*) and 1 of ($x_4_*) and 2 of ($x_3_*) and 7 of ($x_2_*) and 6 of ($x_1_*))) or
            ((3 of ($x_10_*) and 1 of ($x_4_*) and 2 of ($x_3_*) and 8 of ($x_2_*) and 4 of ($x_1_*))) or
            ((3 of ($x_10_*) and 1 of ($x_4_*) and 3 of ($x_3_*) and 17 of ($x_1_*))) or
            ((3 of ($x_10_*) and 1 of ($x_4_*) and 3 of ($x_3_*) and 1 of ($x_2_*) and 15 of ($x_1_*))) or
            ((3 of ($x_10_*) and 1 of ($x_4_*) and 3 of ($x_3_*) and 2 of ($x_2_*) and 13 of ($x_1_*))) or
            ((3 of ($x_10_*) and 1 of ($x_4_*) and 3 of ($x_3_*) and 3 of ($x_2_*) and 11 of ($x_1_*))) or
            ((3 of ($x_10_*) and 1 of ($x_4_*) and 3 of ($x_3_*) and 4 of ($x_2_*) and 9 of ($x_1_*))) or
            ((3 of ($x_10_*) and 1 of ($x_4_*) and 3 of ($x_3_*) and 5 of ($x_2_*) and 7 of ($x_1_*))) or
            ((3 of ($x_10_*) and 1 of ($x_4_*) and 3 of ($x_3_*) and 6 of ($x_2_*) and 5 of ($x_1_*))) or
            ((3 of ($x_10_*) and 1 of ($x_4_*) and 3 of ($x_3_*) and 7 of ($x_2_*) and 3 of ($x_1_*))) or
            ((3 of ($x_10_*) and 1 of ($x_4_*) and 3 of ($x_3_*) and 8 of ($x_2_*) and 1 of ($x_1_*))) or
            ((3 of ($x_10_*) and 1 of ($x_5_*) and 25 of ($x_1_*))) or
            ((3 of ($x_10_*) and 1 of ($x_5_*) and 1 of ($x_2_*) and 23 of ($x_1_*))) or
            ((3 of ($x_10_*) and 1 of ($x_5_*) and 2 of ($x_2_*) and 21 of ($x_1_*))) or
            ((3 of ($x_10_*) and 1 of ($x_5_*) and 3 of ($x_2_*) and 19 of ($x_1_*))) or
            ((3 of ($x_10_*) and 1 of ($x_5_*) and 4 of ($x_2_*) and 17 of ($x_1_*))) or
            ((3 of ($x_10_*) and 1 of ($x_5_*) and 5 of ($x_2_*) and 15 of ($x_1_*))) or
            ((3 of ($x_10_*) and 1 of ($x_5_*) and 6 of ($x_2_*) and 13 of ($x_1_*))) or
            ((3 of ($x_10_*) and 1 of ($x_5_*) and 7 of ($x_2_*) and 11 of ($x_1_*))) or
            ((3 of ($x_10_*) and 1 of ($x_5_*) and 8 of ($x_2_*) and 9 of ($x_1_*))) or
            ((3 of ($x_10_*) and 1 of ($x_5_*) and 1 of ($x_3_*) and 22 of ($x_1_*))) or
            ((3 of ($x_10_*) and 1 of ($x_5_*) and 1 of ($x_3_*) and 1 of ($x_2_*) and 20 of ($x_1_*))) or
            ((3 of ($x_10_*) and 1 of ($x_5_*) and 1 of ($x_3_*) and 2 of ($x_2_*) and 18 of ($x_1_*))) or
            ((3 of ($x_10_*) and 1 of ($x_5_*) and 1 of ($x_3_*) and 3 of ($x_2_*) and 16 of ($x_1_*))) or
            ((3 of ($x_10_*) and 1 of ($x_5_*) and 1 of ($x_3_*) and 4 of ($x_2_*) and 14 of ($x_1_*))) or
            ((3 of ($x_10_*) and 1 of ($x_5_*) and 1 of ($x_3_*) and 5 of ($x_2_*) and 12 of ($x_1_*))) or
            ((3 of ($x_10_*) and 1 of ($x_5_*) and 1 of ($x_3_*) and 6 of ($x_2_*) and 10 of ($x_1_*))) or
            ((3 of ($x_10_*) and 1 of ($x_5_*) and 1 of ($x_3_*) and 7 of ($x_2_*) and 8 of ($x_1_*))) or
            ((3 of ($x_10_*) and 1 of ($x_5_*) and 1 of ($x_3_*) and 8 of ($x_2_*) and 6 of ($x_1_*))) or
            ((3 of ($x_10_*) and 1 of ($x_5_*) and 2 of ($x_3_*) and 19 of ($x_1_*))) or
            ((3 of ($x_10_*) and 1 of ($x_5_*) and 2 of ($x_3_*) and 1 of ($x_2_*) and 17 of ($x_1_*))) or
            ((3 of ($x_10_*) and 1 of ($x_5_*) and 2 of ($x_3_*) and 2 of ($x_2_*) and 15 of ($x_1_*))) or
            ((3 of ($x_10_*) and 1 of ($x_5_*) and 2 of ($x_3_*) and 3 of ($x_2_*) and 13 of ($x_1_*))) or
            ((3 of ($x_10_*) and 1 of ($x_5_*) and 2 of ($x_3_*) and 4 of ($x_2_*) and 11 of ($x_1_*))) or
            ((3 of ($x_10_*) and 1 of ($x_5_*) and 2 of ($x_3_*) and 5 of ($x_2_*) and 9 of ($x_1_*))) or
            ((3 of ($x_10_*) and 1 of ($x_5_*) and 2 of ($x_3_*) and 6 of ($x_2_*) and 7 of ($x_1_*))) or
            ((3 of ($x_10_*) and 1 of ($x_5_*) and 2 of ($x_3_*) and 7 of ($x_2_*) and 5 of ($x_1_*))) or
            ((3 of ($x_10_*) and 1 of ($x_5_*) and 2 of ($x_3_*) and 8 of ($x_2_*) and 3 of ($x_1_*))) or
            ((3 of ($x_10_*) and 1 of ($x_5_*) and 3 of ($x_3_*) and 16 of ($x_1_*))) or
            ((3 of ($x_10_*) and 1 of ($x_5_*) and 3 of ($x_3_*) and 1 of ($x_2_*) and 14 of ($x_1_*))) or
            ((3 of ($x_10_*) and 1 of ($x_5_*) and 3 of ($x_3_*) and 2 of ($x_2_*) and 12 of ($x_1_*))) or
            ((3 of ($x_10_*) and 1 of ($x_5_*) and 3 of ($x_3_*) and 3 of ($x_2_*) and 10 of ($x_1_*))) or
            ((3 of ($x_10_*) and 1 of ($x_5_*) and 3 of ($x_3_*) and 4 of ($x_2_*) and 8 of ($x_1_*))) or
            ((3 of ($x_10_*) and 1 of ($x_5_*) and 3 of ($x_3_*) and 5 of ($x_2_*) and 6 of ($x_1_*))) or
            ((3 of ($x_10_*) and 1 of ($x_5_*) and 3 of ($x_3_*) and 6 of ($x_2_*) and 4 of ($x_1_*))) or
            ((3 of ($x_10_*) and 1 of ($x_5_*) and 3 of ($x_3_*) and 7 of ($x_2_*) and 2 of ($x_1_*))) or
            ((3 of ($x_10_*) and 1 of ($x_5_*) and 3 of ($x_3_*) and 8 of ($x_2_*))) or
            ((3 of ($x_10_*) and 1 of ($x_5_*) and 1 of ($x_4_*) and 21 of ($x_1_*))) or
            ((3 of ($x_10_*) and 1 of ($x_5_*) and 1 of ($x_4_*) and 1 of ($x_2_*) and 19 of ($x_1_*))) or
            ((3 of ($x_10_*) and 1 of ($x_5_*) and 1 of ($x_4_*) and 2 of ($x_2_*) and 17 of ($x_1_*))) or
            ((3 of ($x_10_*) and 1 of ($x_5_*) and 1 of ($x_4_*) and 3 of ($x_2_*) and 15 of ($x_1_*))) or
            ((3 of ($x_10_*) and 1 of ($x_5_*) and 1 of ($x_4_*) and 4 of ($x_2_*) and 13 of ($x_1_*))) or
            ((3 of ($x_10_*) and 1 of ($x_5_*) and 1 of ($x_4_*) and 5 of ($x_2_*) and 11 of ($x_1_*))) or
            ((3 of ($x_10_*) and 1 of ($x_5_*) and 1 of ($x_4_*) and 6 of ($x_2_*) and 9 of ($x_1_*))) or
            ((3 of ($x_10_*) and 1 of ($x_5_*) and 1 of ($x_4_*) and 7 of ($x_2_*) and 7 of ($x_1_*))) or
            ((3 of ($x_10_*) and 1 of ($x_5_*) and 1 of ($x_4_*) and 8 of ($x_2_*) and 5 of ($x_1_*))) or
            ((3 of ($x_10_*) and 1 of ($x_5_*) and 1 of ($x_4_*) and 1 of ($x_3_*) and 18 of ($x_1_*))) or
            ((3 of ($x_10_*) and 1 of ($x_5_*) and 1 of ($x_4_*) and 1 of ($x_3_*) and 1 of ($x_2_*) and 16 of ($x_1_*))) or
            ((3 of ($x_10_*) and 1 of ($x_5_*) and 1 of ($x_4_*) and 1 of ($x_3_*) and 2 of ($x_2_*) and 14 of ($x_1_*))) or
            ((3 of ($x_10_*) and 1 of ($x_5_*) and 1 of ($x_4_*) and 1 of ($x_3_*) and 3 of ($x_2_*) and 12 of ($x_1_*))) or
            ((3 of ($x_10_*) and 1 of ($x_5_*) and 1 of ($x_4_*) and 1 of ($x_3_*) and 4 of ($x_2_*) and 10 of ($x_1_*))) or
            ((3 of ($x_10_*) and 1 of ($x_5_*) and 1 of ($x_4_*) and 1 of ($x_3_*) and 5 of ($x_2_*) and 8 of ($x_1_*))) or
            ((3 of ($x_10_*) and 1 of ($x_5_*) and 1 of ($x_4_*) and 1 of ($x_3_*) and 6 of ($x_2_*) and 6 of ($x_1_*))) or
            ((3 of ($x_10_*) and 1 of ($x_5_*) and 1 of ($x_4_*) and 1 of ($x_3_*) and 7 of ($x_2_*) and 4 of ($x_1_*))) or
            ((3 of ($x_10_*) and 1 of ($x_5_*) and 1 of ($x_4_*) and 1 of ($x_3_*) and 8 of ($x_2_*) and 2 of ($x_1_*))) or
            ((3 of ($x_10_*) and 1 of ($x_5_*) and 1 of ($x_4_*) and 2 of ($x_3_*) and 15 of ($x_1_*))) or
            ((3 of ($x_10_*) and 1 of ($x_5_*) and 1 of ($x_4_*) and 2 of ($x_3_*) and 1 of ($x_2_*) and 13 of ($x_1_*))) or
            ((3 of ($x_10_*) and 1 of ($x_5_*) and 1 of ($x_4_*) and 2 of ($x_3_*) and 2 of ($x_2_*) and 11 of ($x_1_*))) or
            ((3 of ($x_10_*) and 1 of ($x_5_*) and 1 of ($x_4_*) and 2 of ($x_3_*) and 3 of ($x_2_*) and 9 of ($x_1_*))) or
            ((3 of ($x_10_*) and 1 of ($x_5_*) and 1 of ($x_4_*) and 2 of ($x_3_*) and 4 of ($x_2_*) and 7 of ($x_1_*))) or
            ((3 of ($x_10_*) and 1 of ($x_5_*) and 1 of ($x_4_*) and 2 of ($x_3_*) and 5 of ($x_2_*) and 5 of ($x_1_*))) or
            ((3 of ($x_10_*) and 1 of ($x_5_*) and 1 of ($x_4_*) and 2 of ($x_3_*) and 6 of ($x_2_*) and 3 of ($x_1_*))) or
            ((3 of ($x_10_*) and 1 of ($x_5_*) and 1 of ($x_4_*) and 2 of ($x_3_*) and 7 of ($x_2_*) and 1 of ($x_1_*))) or
            ((3 of ($x_10_*) and 1 of ($x_5_*) and 1 of ($x_4_*) and 2 of ($x_3_*) and 8 of ($x_2_*))) or
            ((3 of ($x_10_*) and 1 of ($x_5_*) and 1 of ($x_4_*) and 3 of ($x_3_*) and 12 of ($x_1_*))) or
            ((3 of ($x_10_*) and 1 of ($x_5_*) and 1 of ($x_4_*) and 3 of ($x_3_*) and 1 of ($x_2_*) and 10 of ($x_1_*))) or
            ((3 of ($x_10_*) and 1 of ($x_5_*) and 1 of ($x_4_*) and 3 of ($x_3_*) and 2 of ($x_2_*) and 8 of ($x_1_*))) or
            ((3 of ($x_10_*) and 1 of ($x_5_*) and 1 of ($x_4_*) and 3 of ($x_3_*) and 3 of ($x_2_*) and 6 of ($x_1_*))) or
            ((3 of ($x_10_*) and 1 of ($x_5_*) and 1 of ($x_4_*) and 3 of ($x_3_*) and 4 of ($x_2_*) and 4 of ($x_1_*))) or
            ((3 of ($x_10_*) and 1 of ($x_5_*) and 1 of ($x_4_*) and 3 of ($x_3_*) and 5 of ($x_2_*) and 2 of ($x_1_*))) or
            ((3 of ($x_10_*) and 1 of ($x_5_*) and 1 of ($x_4_*) and 3 of ($x_3_*) and 6 of ($x_2_*))) or
            ((3 of ($x_10_*) and 2 of ($x_5_*) and 20 of ($x_1_*))) or
            ((3 of ($x_10_*) and 2 of ($x_5_*) and 1 of ($x_2_*) and 18 of ($x_1_*))) or
            ((3 of ($x_10_*) and 2 of ($x_5_*) and 2 of ($x_2_*) and 16 of ($x_1_*))) or
            ((3 of ($x_10_*) and 2 of ($x_5_*) and 3 of ($x_2_*) and 14 of ($x_1_*))) or
            ((3 of ($x_10_*) and 2 of ($x_5_*) and 4 of ($x_2_*) and 12 of ($x_1_*))) or
            ((3 of ($x_10_*) and 2 of ($x_5_*) and 5 of ($x_2_*) and 10 of ($x_1_*))) or
            ((3 of ($x_10_*) and 2 of ($x_5_*) and 6 of ($x_2_*) and 8 of ($x_1_*))) or
            ((3 of ($x_10_*) and 2 of ($x_5_*) and 7 of ($x_2_*) and 6 of ($x_1_*))) or
            ((3 of ($x_10_*) and 2 of ($x_5_*) and 8 of ($x_2_*) and 4 of ($x_1_*))) or
            ((3 of ($x_10_*) and 2 of ($x_5_*) and 1 of ($x_3_*) and 17 of ($x_1_*))) or
            ((3 of ($x_10_*) and 2 of ($x_5_*) and 1 of ($x_3_*) and 1 of ($x_2_*) and 15 of ($x_1_*))) or
            ((3 of ($x_10_*) and 2 of ($x_5_*) and 1 of ($x_3_*) and 2 of ($x_2_*) and 13 of ($x_1_*))) or
            ((3 of ($x_10_*) and 2 of ($x_5_*) and 1 of ($x_3_*) and 3 of ($x_2_*) and 11 of ($x_1_*))) or
            ((3 of ($x_10_*) and 2 of ($x_5_*) and 1 of ($x_3_*) and 4 of ($x_2_*) and 9 of ($x_1_*))) or
            ((3 of ($x_10_*) and 2 of ($x_5_*) and 1 of ($x_3_*) and 5 of ($x_2_*) and 7 of ($x_1_*))) or
            ((3 of ($x_10_*) and 2 of ($x_5_*) and 1 of ($x_3_*) and 6 of ($x_2_*) and 5 of ($x_1_*))) or
            ((3 of ($x_10_*) and 2 of ($x_5_*) and 1 of ($x_3_*) and 7 of ($x_2_*) and 3 of ($x_1_*))) or
            ((3 of ($x_10_*) and 2 of ($x_5_*) and 1 of ($x_3_*) and 8 of ($x_2_*) and 1 of ($x_1_*))) or
            ((3 of ($x_10_*) and 2 of ($x_5_*) and 2 of ($x_3_*) and 14 of ($x_1_*))) or
            ((3 of ($x_10_*) and 2 of ($x_5_*) and 2 of ($x_3_*) and 1 of ($x_2_*) and 12 of ($x_1_*))) or
            ((3 of ($x_10_*) and 2 of ($x_5_*) and 2 of ($x_3_*) and 2 of ($x_2_*) and 10 of ($x_1_*))) or
            ((3 of ($x_10_*) and 2 of ($x_5_*) and 2 of ($x_3_*) and 3 of ($x_2_*) and 8 of ($x_1_*))) or
            ((3 of ($x_10_*) and 2 of ($x_5_*) and 2 of ($x_3_*) and 4 of ($x_2_*) and 6 of ($x_1_*))) or
            ((3 of ($x_10_*) and 2 of ($x_5_*) and 2 of ($x_3_*) and 5 of ($x_2_*) and 4 of ($x_1_*))) or
            ((3 of ($x_10_*) and 2 of ($x_5_*) and 2 of ($x_3_*) and 6 of ($x_2_*) and 2 of ($x_1_*))) or
            ((3 of ($x_10_*) and 2 of ($x_5_*) and 2 of ($x_3_*) and 7 of ($x_2_*))) or
            ((3 of ($x_10_*) and 2 of ($x_5_*) and 3 of ($x_3_*) and 11 of ($x_1_*))) or
            ((3 of ($x_10_*) and 2 of ($x_5_*) and 3 of ($x_3_*) and 1 of ($x_2_*) and 9 of ($x_1_*))) or
            ((3 of ($x_10_*) and 2 of ($x_5_*) and 3 of ($x_3_*) and 2 of ($x_2_*) and 7 of ($x_1_*))) or
            ((3 of ($x_10_*) and 2 of ($x_5_*) and 3 of ($x_3_*) and 3 of ($x_2_*) and 5 of ($x_1_*))) or
            ((3 of ($x_10_*) and 2 of ($x_5_*) and 3 of ($x_3_*) and 4 of ($x_2_*) and 3 of ($x_1_*))) or
            ((3 of ($x_10_*) and 2 of ($x_5_*) and 3 of ($x_3_*) and 5 of ($x_2_*) and 1 of ($x_1_*))) or
            ((3 of ($x_10_*) and 2 of ($x_5_*) and 3 of ($x_3_*) and 6 of ($x_2_*))) or
            ((3 of ($x_10_*) and 2 of ($x_5_*) and 1 of ($x_4_*) and 16 of ($x_1_*))) or
            ((3 of ($x_10_*) and 2 of ($x_5_*) and 1 of ($x_4_*) and 1 of ($x_2_*) and 14 of ($x_1_*))) or
            ((3 of ($x_10_*) and 2 of ($x_5_*) and 1 of ($x_4_*) and 2 of ($x_2_*) and 12 of ($x_1_*))) or
            ((3 of ($x_10_*) and 2 of ($x_5_*) and 1 of ($x_4_*) and 3 of ($x_2_*) and 10 of ($x_1_*))) or
            ((3 of ($x_10_*) and 2 of ($x_5_*) and 1 of ($x_4_*) and 4 of ($x_2_*) and 8 of ($x_1_*))) or
            ((3 of ($x_10_*) and 2 of ($x_5_*) and 1 of ($x_4_*) and 5 of ($x_2_*) and 6 of ($x_1_*))) or
            ((3 of ($x_10_*) and 2 of ($x_5_*) and 1 of ($x_4_*) and 6 of ($x_2_*) and 4 of ($x_1_*))) or
            ((3 of ($x_10_*) and 2 of ($x_5_*) and 1 of ($x_4_*) and 7 of ($x_2_*) and 2 of ($x_1_*))) or
            ((3 of ($x_10_*) and 2 of ($x_5_*) and 1 of ($x_4_*) and 8 of ($x_2_*))) or
            ((3 of ($x_10_*) and 2 of ($x_5_*) and 1 of ($x_4_*) and 1 of ($x_3_*) and 13 of ($x_1_*))) or
            ((3 of ($x_10_*) and 2 of ($x_5_*) and 1 of ($x_4_*) and 1 of ($x_3_*) and 1 of ($x_2_*) and 11 of ($x_1_*))) or
            ((3 of ($x_10_*) and 2 of ($x_5_*) and 1 of ($x_4_*) and 1 of ($x_3_*) and 2 of ($x_2_*) and 9 of ($x_1_*))) or
            ((3 of ($x_10_*) and 2 of ($x_5_*) and 1 of ($x_4_*) and 1 of ($x_3_*) and 3 of ($x_2_*) and 7 of ($x_1_*))) or
            ((3 of ($x_10_*) and 2 of ($x_5_*) and 1 of ($x_4_*) and 1 of ($x_3_*) and 4 of ($x_2_*) and 5 of ($x_1_*))) or
            ((3 of ($x_10_*) and 2 of ($x_5_*) and 1 of ($x_4_*) and 1 of ($x_3_*) and 5 of ($x_2_*) and 3 of ($x_1_*))) or
            ((3 of ($x_10_*) and 2 of ($x_5_*) and 1 of ($x_4_*) and 1 of ($x_3_*) and 6 of ($x_2_*) and 1 of ($x_1_*))) or
            ((3 of ($x_10_*) and 2 of ($x_5_*) and 1 of ($x_4_*) and 1 of ($x_3_*) and 7 of ($x_2_*))) or
            ((3 of ($x_10_*) and 2 of ($x_5_*) and 1 of ($x_4_*) and 2 of ($x_3_*) and 10 of ($x_1_*))) or
            ((3 of ($x_10_*) and 2 of ($x_5_*) and 1 of ($x_4_*) and 2 of ($x_3_*) and 1 of ($x_2_*) and 8 of ($x_1_*))) or
            ((3 of ($x_10_*) and 2 of ($x_5_*) and 1 of ($x_4_*) and 2 of ($x_3_*) and 2 of ($x_2_*) and 6 of ($x_1_*))) or
            ((3 of ($x_10_*) and 2 of ($x_5_*) and 1 of ($x_4_*) and 2 of ($x_3_*) and 3 of ($x_2_*) and 4 of ($x_1_*))) or
            ((3 of ($x_10_*) and 2 of ($x_5_*) and 1 of ($x_4_*) and 2 of ($x_3_*) and 4 of ($x_2_*) and 2 of ($x_1_*))) or
            ((3 of ($x_10_*) and 2 of ($x_5_*) and 1 of ($x_4_*) and 2 of ($x_3_*) and 5 of ($x_2_*))) or
            ((3 of ($x_10_*) and 2 of ($x_5_*) and 1 of ($x_4_*) and 3 of ($x_3_*) and 7 of ($x_1_*))) or
            ((3 of ($x_10_*) and 2 of ($x_5_*) and 1 of ($x_4_*) and 3 of ($x_3_*) and 1 of ($x_2_*) and 5 of ($x_1_*))) or
            ((3 of ($x_10_*) and 2 of ($x_5_*) and 1 of ($x_4_*) and 3 of ($x_3_*) and 2 of ($x_2_*) and 3 of ($x_1_*))) or
            ((3 of ($x_10_*) and 2 of ($x_5_*) and 1 of ($x_4_*) and 3 of ($x_3_*) and 3 of ($x_2_*) and 1 of ($x_1_*))) or
            ((3 of ($x_10_*) and 2 of ($x_5_*) and 1 of ($x_4_*) and 3 of ($x_3_*) and 4 of ($x_2_*))) or
            ((3 of ($x_10_*) and 3 of ($x_5_*) and 15 of ($x_1_*))) or
            ((3 of ($x_10_*) and 3 of ($x_5_*) and 1 of ($x_2_*) and 13 of ($x_1_*))) or
            ((3 of ($x_10_*) and 3 of ($x_5_*) and 2 of ($x_2_*) and 11 of ($x_1_*))) or
            ((3 of ($x_10_*) and 3 of ($x_5_*) and 3 of ($x_2_*) and 9 of ($x_1_*))) or
            ((3 of ($x_10_*) and 3 of ($x_5_*) and 4 of ($x_2_*) and 7 of ($x_1_*))) or
            ((3 of ($x_10_*) and 3 of ($x_5_*) and 5 of ($x_2_*) and 5 of ($x_1_*))) or
            ((3 of ($x_10_*) and 3 of ($x_5_*) and 6 of ($x_2_*) and 3 of ($x_1_*))) or
            ((3 of ($x_10_*) and 3 of ($x_5_*) and 7 of ($x_2_*) and 1 of ($x_1_*))) or
            ((3 of ($x_10_*) and 3 of ($x_5_*) and 8 of ($x_2_*))) or
            ((3 of ($x_10_*) and 3 of ($x_5_*) and 1 of ($x_3_*) and 12 of ($x_1_*))) or
            ((3 of ($x_10_*) and 3 of ($x_5_*) and 1 of ($x_3_*) and 1 of ($x_2_*) and 10 of ($x_1_*))) or
            ((3 of ($x_10_*) and 3 of ($x_5_*) and 1 of ($x_3_*) and 2 of ($x_2_*) and 8 of ($x_1_*))) or
            ((3 of ($x_10_*) and 3 of ($x_5_*) and 1 of ($x_3_*) and 3 of ($x_2_*) and 6 of ($x_1_*))) or
            ((3 of ($x_10_*) and 3 of ($x_5_*) and 1 of ($x_3_*) and 4 of ($x_2_*) and 4 of ($x_1_*))) or
            ((3 of ($x_10_*) and 3 of ($x_5_*) and 1 of ($x_3_*) and 5 of ($x_2_*) and 2 of ($x_1_*))) or
            ((3 of ($x_10_*) and 3 of ($x_5_*) and 1 of ($x_3_*) and 6 of ($x_2_*))) or
            ((3 of ($x_10_*) and 3 of ($x_5_*) and 2 of ($x_3_*) and 9 of ($x_1_*))) or
            ((3 of ($x_10_*) and 3 of ($x_5_*) and 2 of ($x_3_*) and 1 of ($x_2_*) and 7 of ($x_1_*))) or
            ((3 of ($x_10_*) and 3 of ($x_5_*) and 2 of ($x_3_*) and 2 of ($x_2_*) and 5 of ($x_1_*))) or
            ((3 of ($x_10_*) and 3 of ($x_5_*) and 2 of ($x_3_*) and 3 of ($x_2_*) and 3 of ($x_1_*))) or
            ((3 of ($x_10_*) and 3 of ($x_5_*) and 2 of ($x_3_*) and 4 of ($x_2_*) and 1 of ($x_1_*))) or
            ((3 of ($x_10_*) and 3 of ($x_5_*) and 2 of ($x_3_*) and 5 of ($x_2_*))) or
            ((3 of ($x_10_*) and 3 of ($x_5_*) and 3 of ($x_3_*) and 6 of ($x_1_*))) or
            ((3 of ($x_10_*) and 3 of ($x_5_*) and 3 of ($x_3_*) and 1 of ($x_2_*) and 4 of ($x_1_*))) or
            ((3 of ($x_10_*) and 3 of ($x_5_*) and 3 of ($x_3_*) and 2 of ($x_2_*) and 2 of ($x_1_*))) or
            ((3 of ($x_10_*) and 3 of ($x_5_*) and 3 of ($x_3_*) and 3 of ($x_2_*))) or
            ((3 of ($x_10_*) and 3 of ($x_5_*) and 1 of ($x_4_*) and 11 of ($x_1_*))) or
            ((3 of ($x_10_*) and 3 of ($x_5_*) and 1 of ($x_4_*) and 1 of ($x_2_*) and 9 of ($x_1_*))) or
            ((3 of ($x_10_*) and 3 of ($x_5_*) and 1 of ($x_4_*) and 2 of ($x_2_*) and 7 of ($x_1_*))) or
            ((3 of ($x_10_*) and 3 of ($x_5_*) and 1 of ($x_4_*) and 3 of ($x_2_*) and 5 of ($x_1_*))) or
            ((3 of ($x_10_*) and 3 of ($x_5_*) and 1 of ($x_4_*) and 4 of ($x_2_*) and 3 of ($x_1_*))) or
            ((3 of ($x_10_*) and 3 of ($x_5_*) and 1 of ($x_4_*) and 5 of ($x_2_*) and 1 of ($x_1_*))) or
            ((3 of ($x_10_*) and 3 of ($x_5_*) and 1 of ($x_4_*) and 6 of ($x_2_*))) or
            ((3 of ($x_10_*) and 3 of ($x_5_*) and 1 of ($x_4_*) and 1 of ($x_3_*) and 8 of ($x_1_*))) or
            ((3 of ($x_10_*) and 3 of ($x_5_*) and 1 of ($x_4_*) and 1 of ($x_3_*) and 1 of ($x_2_*) and 6 of ($x_1_*))) or
            ((3 of ($x_10_*) and 3 of ($x_5_*) and 1 of ($x_4_*) and 1 of ($x_3_*) and 2 of ($x_2_*) and 4 of ($x_1_*))) or
            ((3 of ($x_10_*) and 3 of ($x_5_*) and 1 of ($x_4_*) and 1 of ($x_3_*) and 3 of ($x_2_*) and 2 of ($x_1_*))) or
            ((3 of ($x_10_*) and 3 of ($x_5_*) and 1 of ($x_4_*) and 1 of ($x_3_*) and 4 of ($x_2_*))) or
            ((3 of ($x_10_*) and 3 of ($x_5_*) and 1 of ($x_4_*) and 2 of ($x_3_*) and 5 of ($x_1_*))) or
            ((3 of ($x_10_*) and 3 of ($x_5_*) and 1 of ($x_4_*) and 2 of ($x_3_*) and 1 of ($x_2_*) and 3 of ($x_1_*))) or
            ((3 of ($x_10_*) and 3 of ($x_5_*) and 1 of ($x_4_*) and 2 of ($x_3_*) and 2 of ($x_2_*) and 1 of ($x_1_*))) or
            ((3 of ($x_10_*) and 3 of ($x_5_*) and 1 of ($x_4_*) and 2 of ($x_3_*) and 3 of ($x_2_*))) or
            ((3 of ($x_10_*) and 3 of ($x_5_*) and 1 of ($x_4_*) and 3 of ($x_3_*) and 2 of ($x_1_*))) or
            ((3 of ($x_10_*) and 3 of ($x_5_*) and 1 of ($x_4_*) and 3 of ($x_3_*) and 1 of ($x_2_*))) or
            ((4 of ($x_10_*) and 20 of ($x_1_*))) or
            ((4 of ($x_10_*) and 1 of ($x_2_*) and 18 of ($x_1_*))) or
            ((4 of ($x_10_*) and 2 of ($x_2_*) and 16 of ($x_1_*))) or
            ((4 of ($x_10_*) and 3 of ($x_2_*) and 14 of ($x_1_*))) or
            ((4 of ($x_10_*) and 4 of ($x_2_*) and 12 of ($x_1_*))) or
            ((4 of ($x_10_*) and 5 of ($x_2_*) and 10 of ($x_1_*))) or
            ((4 of ($x_10_*) and 6 of ($x_2_*) and 8 of ($x_1_*))) or
            ((4 of ($x_10_*) and 7 of ($x_2_*) and 6 of ($x_1_*))) or
            ((4 of ($x_10_*) and 8 of ($x_2_*) and 4 of ($x_1_*))) or
            ((4 of ($x_10_*) and 1 of ($x_3_*) and 17 of ($x_1_*))) or
            ((4 of ($x_10_*) and 1 of ($x_3_*) and 1 of ($x_2_*) and 15 of ($x_1_*))) or
            ((4 of ($x_10_*) and 1 of ($x_3_*) and 2 of ($x_2_*) and 13 of ($x_1_*))) or
            ((4 of ($x_10_*) and 1 of ($x_3_*) and 3 of ($x_2_*) and 11 of ($x_1_*))) or
            ((4 of ($x_10_*) and 1 of ($x_3_*) and 4 of ($x_2_*) and 9 of ($x_1_*))) or
            ((4 of ($x_10_*) and 1 of ($x_3_*) and 5 of ($x_2_*) and 7 of ($x_1_*))) or
            ((4 of ($x_10_*) and 1 of ($x_3_*) and 6 of ($x_2_*) and 5 of ($x_1_*))) or
            ((4 of ($x_10_*) and 1 of ($x_3_*) and 7 of ($x_2_*) and 3 of ($x_1_*))) or
            ((4 of ($x_10_*) and 1 of ($x_3_*) and 8 of ($x_2_*) and 1 of ($x_1_*))) or
            ((4 of ($x_10_*) and 2 of ($x_3_*) and 14 of ($x_1_*))) or
            ((4 of ($x_10_*) and 2 of ($x_3_*) and 1 of ($x_2_*) and 12 of ($x_1_*))) or
            ((4 of ($x_10_*) and 2 of ($x_3_*) and 2 of ($x_2_*) and 10 of ($x_1_*))) or
            ((4 of ($x_10_*) and 2 of ($x_3_*) and 3 of ($x_2_*) and 8 of ($x_1_*))) or
            ((4 of ($x_10_*) and 2 of ($x_3_*) and 4 of ($x_2_*) and 6 of ($x_1_*))) or
            ((4 of ($x_10_*) and 2 of ($x_3_*) and 5 of ($x_2_*) and 4 of ($x_1_*))) or
            ((4 of ($x_10_*) and 2 of ($x_3_*) and 6 of ($x_2_*) and 2 of ($x_1_*))) or
            ((4 of ($x_10_*) and 2 of ($x_3_*) and 7 of ($x_2_*))) or
            ((4 of ($x_10_*) and 3 of ($x_3_*) and 11 of ($x_1_*))) or
            ((4 of ($x_10_*) and 3 of ($x_3_*) and 1 of ($x_2_*) and 9 of ($x_1_*))) or
            ((4 of ($x_10_*) and 3 of ($x_3_*) and 2 of ($x_2_*) and 7 of ($x_1_*))) or
            ((4 of ($x_10_*) and 3 of ($x_3_*) and 3 of ($x_2_*) and 5 of ($x_1_*))) or
            ((4 of ($x_10_*) and 3 of ($x_3_*) and 4 of ($x_2_*) and 3 of ($x_1_*))) or
            ((4 of ($x_10_*) and 3 of ($x_3_*) and 5 of ($x_2_*) and 1 of ($x_1_*))) or
            ((4 of ($x_10_*) and 3 of ($x_3_*) and 6 of ($x_2_*))) or
            ((4 of ($x_10_*) and 1 of ($x_4_*) and 16 of ($x_1_*))) or
            ((4 of ($x_10_*) and 1 of ($x_4_*) and 1 of ($x_2_*) and 14 of ($x_1_*))) or
            ((4 of ($x_10_*) and 1 of ($x_4_*) and 2 of ($x_2_*) and 12 of ($x_1_*))) or
            ((4 of ($x_10_*) and 1 of ($x_4_*) and 3 of ($x_2_*) and 10 of ($x_1_*))) or
            ((4 of ($x_10_*) and 1 of ($x_4_*) and 4 of ($x_2_*) and 8 of ($x_1_*))) or
            ((4 of ($x_10_*) and 1 of ($x_4_*) and 5 of ($x_2_*) and 6 of ($x_1_*))) or
            ((4 of ($x_10_*) and 1 of ($x_4_*) and 6 of ($x_2_*) and 4 of ($x_1_*))) or
            ((4 of ($x_10_*) and 1 of ($x_4_*) and 7 of ($x_2_*) and 2 of ($x_1_*))) or
            ((4 of ($x_10_*) and 1 of ($x_4_*) and 8 of ($x_2_*))) or
            ((4 of ($x_10_*) and 1 of ($x_4_*) and 1 of ($x_3_*) and 13 of ($x_1_*))) or
            ((4 of ($x_10_*) and 1 of ($x_4_*) and 1 of ($x_3_*) and 1 of ($x_2_*) and 11 of ($x_1_*))) or
            ((4 of ($x_10_*) and 1 of ($x_4_*) and 1 of ($x_3_*) and 2 of ($x_2_*) and 9 of ($x_1_*))) or
            ((4 of ($x_10_*) and 1 of ($x_4_*) and 1 of ($x_3_*) and 3 of ($x_2_*) and 7 of ($x_1_*))) or
            ((4 of ($x_10_*) and 1 of ($x_4_*) and 1 of ($x_3_*) and 4 of ($x_2_*) and 5 of ($x_1_*))) or
            ((4 of ($x_10_*) and 1 of ($x_4_*) and 1 of ($x_3_*) and 5 of ($x_2_*) and 3 of ($x_1_*))) or
            ((4 of ($x_10_*) and 1 of ($x_4_*) and 1 of ($x_3_*) and 6 of ($x_2_*) and 1 of ($x_1_*))) or
            ((4 of ($x_10_*) and 1 of ($x_4_*) and 1 of ($x_3_*) and 7 of ($x_2_*))) or
            ((4 of ($x_10_*) and 1 of ($x_4_*) and 2 of ($x_3_*) and 10 of ($x_1_*))) or
            ((4 of ($x_10_*) and 1 of ($x_4_*) and 2 of ($x_3_*) and 1 of ($x_2_*) and 8 of ($x_1_*))) or
            ((4 of ($x_10_*) and 1 of ($x_4_*) and 2 of ($x_3_*) and 2 of ($x_2_*) and 6 of ($x_1_*))) or
            ((4 of ($x_10_*) and 1 of ($x_4_*) and 2 of ($x_3_*) and 3 of ($x_2_*) and 4 of ($x_1_*))) or
            ((4 of ($x_10_*) and 1 of ($x_4_*) and 2 of ($x_3_*) and 4 of ($x_2_*) and 2 of ($x_1_*))) or
            ((4 of ($x_10_*) and 1 of ($x_4_*) and 2 of ($x_3_*) and 5 of ($x_2_*))) or
            ((4 of ($x_10_*) and 1 of ($x_4_*) and 3 of ($x_3_*) and 7 of ($x_1_*))) or
            ((4 of ($x_10_*) and 1 of ($x_4_*) and 3 of ($x_3_*) and 1 of ($x_2_*) and 5 of ($x_1_*))) or
            ((4 of ($x_10_*) and 1 of ($x_4_*) and 3 of ($x_3_*) and 2 of ($x_2_*) and 3 of ($x_1_*))) or
            ((4 of ($x_10_*) and 1 of ($x_4_*) and 3 of ($x_3_*) and 3 of ($x_2_*) and 1 of ($x_1_*))) or
            ((4 of ($x_10_*) and 1 of ($x_4_*) and 3 of ($x_3_*) and 4 of ($x_2_*))) or
            ((4 of ($x_10_*) and 1 of ($x_5_*) and 15 of ($x_1_*))) or
            ((4 of ($x_10_*) and 1 of ($x_5_*) and 1 of ($x_2_*) and 13 of ($x_1_*))) or
            ((4 of ($x_10_*) and 1 of ($x_5_*) and 2 of ($x_2_*) and 11 of ($x_1_*))) or
            ((4 of ($x_10_*) and 1 of ($x_5_*) and 3 of ($x_2_*) and 9 of ($x_1_*))) or
            ((4 of ($x_10_*) and 1 of ($x_5_*) and 4 of ($x_2_*) and 7 of ($x_1_*))) or
            ((4 of ($x_10_*) and 1 of ($x_5_*) and 5 of ($x_2_*) and 5 of ($x_1_*))) or
            ((4 of ($x_10_*) and 1 of ($x_5_*) and 6 of ($x_2_*) and 3 of ($x_1_*))) or
            ((4 of ($x_10_*) and 1 of ($x_5_*) and 7 of ($x_2_*) and 1 of ($x_1_*))) or
            ((4 of ($x_10_*) and 1 of ($x_5_*) and 8 of ($x_2_*))) or
            ((4 of ($x_10_*) and 1 of ($x_5_*) and 1 of ($x_3_*) and 12 of ($x_1_*))) or
            ((4 of ($x_10_*) and 1 of ($x_5_*) and 1 of ($x_3_*) and 1 of ($x_2_*) and 10 of ($x_1_*))) or
            ((4 of ($x_10_*) and 1 of ($x_5_*) and 1 of ($x_3_*) and 2 of ($x_2_*) and 8 of ($x_1_*))) or
            ((4 of ($x_10_*) and 1 of ($x_5_*) and 1 of ($x_3_*) and 3 of ($x_2_*) and 6 of ($x_1_*))) or
            ((4 of ($x_10_*) and 1 of ($x_5_*) and 1 of ($x_3_*) and 4 of ($x_2_*) and 4 of ($x_1_*))) or
            ((4 of ($x_10_*) and 1 of ($x_5_*) and 1 of ($x_3_*) and 5 of ($x_2_*) and 2 of ($x_1_*))) or
            ((4 of ($x_10_*) and 1 of ($x_5_*) and 1 of ($x_3_*) and 6 of ($x_2_*))) or
            ((4 of ($x_10_*) and 1 of ($x_5_*) and 2 of ($x_3_*) and 9 of ($x_1_*))) or
            ((4 of ($x_10_*) and 1 of ($x_5_*) and 2 of ($x_3_*) and 1 of ($x_2_*) and 7 of ($x_1_*))) or
            ((4 of ($x_10_*) and 1 of ($x_5_*) and 2 of ($x_3_*) and 2 of ($x_2_*) and 5 of ($x_1_*))) or
            ((4 of ($x_10_*) and 1 of ($x_5_*) and 2 of ($x_3_*) and 3 of ($x_2_*) and 3 of ($x_1_*))) or
            ((4 of ($x_10_*) and 1 of ($x_5_*) and 2 of ($x_3_*) and 4 of ($x_2_*) and 1 of ($x_1_*))) or
            ((4 of ($x_10_*) and 1 of ($x_5_*) and 2 of ($x_3_*) and 5 of ($x_2_*))) or
            ((4 of ($x_10_*) and 1 of ($x_5_*) and 3 of ($x_3_*) and 6 of ($x_1_*))) or
            ((4 of ($x_10_*) and 1 of ($x_5_*) and 3 of ($x_3_*) and 1 of ($x_2_*) and 4 of ($x_1_*))) or
            ((4 of ($x_10_*) and 1 of ($x_5_*) and 3 of ($x_3_*) and 2 of ($x_2_*) and 2 of ($x_1_*))) or
            ((4 of ($x_10_*) and 1 of ($x_5_*) and 3 of ($x_3_*) and 3 of ($x_2_*))) or
            ((4 of ($x_10_*) and 1 of ($x_5_*) and 1 of ($x_4_*) and 11 of ($x_1_*))) or
            ((4 of ($x_10_*) and 1 of ($x_5_*) and 1 of ($x_4_*) and 1 of ($x_2_*) and 9 of ($x_1_*))) or
            ((4 of ($x_10_*) and 1 of ($x_5_*) and 1 of ($x_4_*) and 2 of ($x_2_*) and 7 of ($x_1_*))) or
            ((4 of ($x_10_*) and 1 of ($x_5_*) and 1 of ($x_4_*) and 3 of ($x_2_*) and 5 of ($x_1_*))) or
            ((4 of ($x_10_*) and 1 of ($x_5_*) and 1 of ($x_4_*) and 4 of ($x_2_*) and 3 of ($x_1_*))) or
            ((4 of ($x_10_*) and 1 of ($x_5_*) and 1 of ($x_4_*) and 5 of ($x_2_*) and 1 of ($x_1_*))) or
            ((4 of ($x_10_*) and 1 of ($x_5_*) and 1 of ($x_4_*) and 6 of ($x_2_*))) or
            ((4 of ($x_10_*) and 1 of ($x_5_*) and 1 of ($x_4_*) and 1 of ($x_3_*) and 8 of ($x_1_*))) or
            ((4 of ($x_10_*) and 1 of ($x_5_*) and 1 of ($x_4_*) and 1 of ($x_3_*) and 1 of ($x_2_*) and 6 of ($x_1_*))) or
            ((4 of ($x_10_*) and 1 of ($x_5_*) and 1 of ($x_4_*) and 1 of ($x_3_*) and 2 of ($x_2_*) and 4 of ($x_1_*))) or
            ((4 of ($x_10_*) and 1 of ($x_5_*) and 1 of ($x_4_*) and 1 of ($x_3_*) and 3 of ($x_2_*) and 2 of ($x_1_*))) or
            ((4 of ($x_10_*) and 1 of ($x_5_*) and 1 of ($x_4_*) and 1 of ($x_3_*) and 4 of ($x_2_*))) or
            ((4 of ($x_10_*) and 1 of ($x_5_*) and 1 of ($x_4_*) and 2 of ($x_3_*) and 5 of ($x_1_*))) or
            ((4 of ($x_10_*) and 1 of ($x_5_*) and 1 of ($x_4_*) and 2 of ($x_3_*) and 1 of ($x_2_*) and 3 of ($x_1_*))) or
            ((4 of ($x_10_*) and 1 of ($x_5_*) and 1 of ($x_4_*) and 2 of ($x_3_*) and 2 of ($x_2_*) and 1 of ($x_1_*))) or
            ((4 of ($x_10_*) and 1 of ($x_5_*) and 1 of ($x_4_*) and 2 of ($x_3_*) and 3 of ($x_2_*))) or
            ((4 of ($x_10_*) and 1 of ($x_5_*) and 1 of ($x_4_*) and 3 of ($x_3_*) and 2 of ($x_1_*))) or
            ((4 of ($x_10_*) and 1 of ($x_5_*) and 1 of ($x_4_*) and 3 of ($x_3_*) and 1 of ($x_2_*))) or
            ((4 of ($x_10_*) and 2 of ($x_5_*) and 10 of ($x_1_*))) or
            ((4 of ($x_10_*) and 2 of ($x_5_*) and 1 of ($x_2_*) and 8 of ($x_1_*))) or
            ((4 of ($x_10_*) and 2 of ($x_5_*) and 2 of ($x_2_*) and 6 of ($x_1_*))) or
            ((4 of ($x_10_*) and 2 of ($x_5_*) and 3 of ($x_2_*) and 4 of ($x_1_*))) or
            ((4 of ($x_10_*) and 2 of ($x_5_*) and 4 of ($x_2_*) and 2 of ($x_1_*))) or
            ((4 of ($x_10_*) and 2 of ($x_5_*) and 5 of ($x_2_*))) or
            ((4 of ($x_10_*) and 2 of ($x_5_*) and 1 of ($x_3_*) and 7 of ($x_1_*))) or
            ((4 of ($x_10_*) and 2 of ($x_5_*) and 1 of ($x_3_*) and 1 of ($x_2_*) and 5 of ($x_1_*))) or
            ((4 of ($x_10_*) and 2 of ($x_5_*) and 1 of ($x_3_*) and 2 of ($x_2_*) and 3 of ($x_1_*))) or
            ((4 of ($x_10_*) and 2 of ($x_5_*) and 1 of ($x_3_*) and 3 of ($x_2_*) and 1 of ($x_1_*))) or
            ((4 of ($x_10_*) and 2 of ($x_5_*) and 1 of ($x_3_*) and 4 of ($x_2_*))) or
            ((4 of ($x_10_*) and 2 of ($x_5_*) and 2 of ($x_3_*) and 4 of ($x_1_*))) or
            ((4 of ($x_10_*) and 2 of ($x_5_*) and 2 of ($x_3_*) and 1 of ($x_2_*) and 2 of ($x_1_*))) or
            ((4 of ($x_10_*) and 2 of ($x_5_*) and 2 of ($x_3_*) and 2 of ($x_2_*))) or
            ((4 of ($x_10_*) and 2 of ($x_5_*) and 3 of ($x_3_*) and 1 of ($x_1_*))) or
            ((4 of ($x_10_*) and 2 of ($x_5_*) and 3 of ($x_3_*) and 1 of ($x_2_*))) or
            ((4 of ($x_10_*) and 2 of ($x_5_*) and 1 of ($x_4_*) and 6 of ($x_1_*))) or
            ((4 of ($x_10_*) and 2 of ($x_5_*) and 1 of ($x_4_*) and 1 of ($x_2_*) and 4 of ($x_1_*))) or
            ((4 of ($x_10_*) and 2 of ($x_5_*) and 1 of ($x_4_*) and 2 of ($x_2_*) and 2 of ($x_1_*))) or
            ((4 of ($x_10_*) and 2 of ($x_5_*) and 1 of ($x_4_*) and 3 of ($x_2_*))) or
            ((4 of ($x_10_*) and 2 of ($x_5_*) and 1 of ($x_4_*) and 1 of ($x_3_*) and 3 of ($x_1_*))) or
            ((4 of ($x_10_*) and 2 of ($x_5_*) and 1 of ($x_4_*) and 1 of ($x_3_*) and 1 of ($x_2_*) and 1 of ($x_1_*))) or
            ((4 of ($x_10_*) and 2 of ($x_5_*) and 1 of ($x_4_*) and 1 of ($x_3_*) and 2 of ($x_2_*))) or
            ((4 of ($x_10_*) and 2 of ($x_5_*) and 1 of ($x_4_*) and 2 of ($x_3_*))) or
            ((4 of ($x_10_*) and 3 of ($x_5_*) and 5 of ($x_1_*))) or
            ((4 of ($x_10_*) and 3 of ($x_5_*) and 1 of ($x_2_*) and 3 of ($x_1_*))) or
            ((4 of ($x_10_*) and 3 of ($x_5_*) and 2 of ($x_2_*) and 1 of ($x_1_*))) or
            ((4 of ($x_10_*) and 3 of ($x_5_*) and 3 of ($x_2_*))) or
            ((4 of ($x_10_*) and 3 of ($x_5_*) and 1 of ($x_3_*) and 2 of ($x_1_*))) or
            ((4 of ($x_10_*) and 3 of ($x_5_*) and 1 of ($x_3_*) and 1 of ($x_2_*))) or
            ((4 of ($x_10_*) and 3 of ($x_5_*) and 2 of ($x_3_*))) or
            ((4 of ($x_10_*) and 3 of ($x_5_*) and 1 of ($x_4_*) and 1 of ($x_1_*))) or
            ((4 of ($x_10_*) and 3 of ($x_5_*) and 1 of ($x_4_*) and 1 of ($x_2_*))) or
            ((4 of ($x_10_*) and 3 of ($x_5_*) and 1 of ($x_4_*) and 1 of ($x_3_*))) or
            (all of ($x*))
        )
}

rule Backdoor_Win32_Koceg_C_2147608228_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Koceg.gen!C"
        threat_id = "2147608228"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Koceg"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {89 45 fc 83 7d fc ff 75 04 33 c0 eb 03 6a 01 58}  //weight: 1, accuracy: High
        $x_3_2 = {39 45 fc 7d 16 8b 45 08 03 45 fc 0f be 00 33 45 0c 8b 4d 08 03 4d fc 88 01 eb d5 8b 45 08}  //weight: 3, accuracy: High
        $x_3_3 = {39 45 fc 7d 25 8b 45 08 03 45 fc 0f be 00 83 f8 30 7c 0e 8b 45 08 03 45 fc 0f be 00 83 f8 39 7e 07}  //weight: 3, accuracy: High
        $x_3_4 = {8b 4d 08 0f b6 44 01 f8 83 e8 30 69 c0 80 96 98 00 8b 4d fc 03 c8 89 4d fc 8b 45 fc}  //weight: 3, accuracy: High
        $x_3_5 = {59 99 b9 30 75 00 00 f7 f9}  //weight: 3, accuracy: High
        $x_3_6 = {ff 33 27 00 00 74 05 e9 ?? 00 00 00 6a 00 68 e8 03 00 00 8d 85}  //weight: 3, accuracy: Low
        $x_1_7 = "oc0chg0:,rjr" ascii //weight: 1
        $x_1_8 = "gzrnmpgp,fnn" ascii //weight: 1
        $x_1_9 = "#Sniff" ascii //weight: 1
        $x_1_10 = "&emails=" ascii //weight: 1
        $x_1_11 = {26 63 69 70 3d 00}  //weight: 1, accuracy: High
        $x_1_12 = {26 6c 69 64 3d 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_3_*) and 7 of ($x_1_*))) or
            ((2 of ($x_3_*) and 4 of ($x_1_*))) or
            ((3 of ($x_3_*) and 1 of ($x_1_*))) or
            ((4 of ($x_3_*))) or
            (all of ($x*))
        )
}

rule Backdoor_Win32_Koceg_D_2147608481_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Koceg.gen!D"
        threat_id = "2147608481"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Koceg"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {89 45 fc 83 7d fc ff 75 04 33 c0 eb 03 6a 01 58}  //weight: 1, accuracy: High
        $x_2_2 = {39 45 fc 7d 16 8b 45 08 03 45 fc 0f be 00 33 45 0c 8b 4d 08 03 4d fc 88 01 eb d5 8b 45 08}  //weight: 2, accuracy: High
        $x_2_3 = {b8 68 58 4d 56 bb 65 d4 85 86 b9 0a 00 00 00 66 ba 58 56 ed 89 5d e4 5b 83 4d fc ff eb 14 6a 01 58 c3}  //weight: 2, accuracy: High
        $x_2_4 = {59 59 0f b6 45 fc 85 c0 75 0d 68 (80|80) 00 ff 15 ?? ?? 40 00 eb 0b 68 10 27 00 00 ff 15}  //weight: 2, accuracy: Low
        $x_1_5 = "%%%02X" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_2_*) and 1 of ($x_1_*))) or
            ((3 of ($x_2_*))) or
            (all of ($x*))
        )
}

rule Backdoor_Win32_Koceg_E_2147610472_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Koceg.gen!E"
        threat_id = "2147610472"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Koceg"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "51"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = "rk %d %d" ascii //weight: 10
        $x_10_2 = "ftp://%s:%s@%s" ascii //weight: 10
        $x_10_3 = "SeShutdownPrivilege" ascii //weight: 10
        $x_10_4 = "Virus" ascii //weight: 10
        $x_10_5 = "Exploit" ascii //weight: 10
        $x_1_6 = {8b 45 08 03 45 fc 0f be 00 33 45 ?? 8b 4d 08 03 4d fc 88 01 eb}  //weight: 1, accuracy: Low
        $x_1_7 = {8b 45 08 03 45 fc 0f be 00 35 ?? ?? ?? ?? 8b 4d 08 03 4d fc 88 01 eb}  //weight: 1, accuracy: Low
        $x_1_8 = {8b 45 08 03 45 ?? 0f be 00 0f be 4d fc 33 ?? 8b 4d f8 03 4d f4 88 41 fe eb}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((5 of ($x_10_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Backdoor_Win32_Koceg_F_2147621291_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Koceg.gen!F"
        threat_id = "2147621291"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Koceg"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {0f be 40 02 83 f8 74}  //weight: 1, accuracy: High
        $x_1_2 = {0f be 40 01 83 f8 69}  //weight: 1, accuracy: High
        $x_1_3 = {6a ff 8d 45 f4 50 68 f6 01 00 00 6a 00 e8}  //weight: 1, accuracy: High
        $x_2_4 = {33 45 0c 8b 4d 08 03 4d fc 88 01 eb d5}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((3 of ($x_1_*))) or
            ((1 of ($x_2_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}


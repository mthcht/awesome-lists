rule Trojan_Win64_VanillaMilkshake_B_2147965317_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/VanillaMilkshake.B!dha"
        threat_id = "2147965317"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "VanillaMilkshake"
        severity = "Critical"
        info = "dha: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_3_1 = {00 52 62 6f 61 74 2e 65 78 65 00}  //weight: 3, accuracy: High
        $x_3_2 = "windowsVer.dll" wide //weight: 3
        $x_3_3 = "!2wE3$rt%#yU*8iO()P{}!QAZXDRGBNJIlkjh786" ascii //weight: 3
        $x_3_4 = "{52A581E88EA6-30BC9A-07A24-9235}" ascii //weight: 3
        $x_2_5 = {00 53 65 72 76 65 72 5f 44 6c 6c 2e 64 6c 6c 00}  //weight: 2, accuracy: High
        $x_2_6 = "%sd.e%sc n%ssh%srewa%s ad%s po%sop%sing T%s %d \"%s\"" ascii //weight: 2
        $x_1_7 = "C:\\Windows\\Temp\\log.txt" ascii //weight: 1
        $x_1_8 = "Samsung Portable SSD Software" wide //weight: 1
        $x_1_9 = "PoetegereWallSttte" ascii //weight: 1
        $x_1_10 = "Inject Engine Start" ascii //weight: 1
        $x_1_11 = "Inject Engine Success" ascii //weight: 1
        $x_1_12 = "MemoryLoadLibrary Fail1" ascii //weight: 1
        $x_1_13 = "%sping 127.0.0.1 -n 2 |find \"abc\" > nul" ascii //weight: 1
        $x_1_14 = "%stasklist /fi \"pid eq %d\" |find \":\" > nul" ascii //weight: 1
        $x_1_15 = "sysWyde.bat" ascii //weight: 1
        $x_1_16 = "Total Byte!!" ascii //weight: 1
        $x_1_17 = "GetPrivateIP!!" ascii //weight: 1
        $x_1_18 = "Connect Reason!!" ascii //weight: 1
        $x_1_19 = "Host Name!!" ascii //weight: 1
        $x_1_20 = "User Name!!" ascii //weight: 1
        $x_1_21 = "fnWSAStartup!!" ascii //weight: 1
        $x_1_22 = "GetPrivateIP fngethostname" ascii //weight: 1
        $x_1_23 = "fngethostbyname!!" ascii //weight: 1
        $x_1_24 = "GetPrivateIP 1!!" ascii //weight: 1
        $x_1_25 = "GetPrivateIP End!!" ascii //weight: 1
        $x_1_26 = "Go to next Connect" ascii //weight: 1
        $x_1_27 = "Get Encrypted Mid Info" ascii //weight: 1
        $x_1_28 = "Get Mid Url PlainText" ascii //weight: 1
        $x_1_29 = "Send Proxy Info" ascii //weight: 1
        $x_1_30 = "Receive Data Fail" ascii //weight: 1
        $x_1_31 = {00 32 31 3a 32 39 3a 35 32 00}  //weight: 1, accuracy: High
        $x_1_32 = {00 31 30 3a 32 38 3a 32 38 00}  //weight: 1, accuracy: High
        $x_1_33 = "~%dk%d.tmp" ascii //weight: 1
        $x_1_34 = "Q3JlYXRlRmlsZVByb2NFeA==" ascii //weight: 1
        $x_1_35 = "?AVCMyCryption" ascii //weight: 1
        $x_1_36 = "?AVCRsaCrypt" ascii //weight: 1
        $x_1_37 = "?AVW3Client" ascii //weight: 1
        $x_1_38 = "?AVHbpHook@" ascii //weight: 1
        $x_1_39 = {3f 41 56 43 5a 69 70 70 65 72 40 40 00}  //weight: 1, accuracy: High
        $x_1_40 = {3f 41 56 43 53 65 72 76 65 72 40 40 00}  //weight: 1, accuracy: High
        $x_1_41 = {00 3d 8d 56 34 12 74}  //weight: 1, accuracy: High
        $x_1_42 = {b9 04 00 00 00 48 6b c9 08 48 8b 54 24 ?? 89 04 0a b8 04 00 00 00 48 6b c0 ?? b9 04 00 00 00 48 6b c9 ?? 48 8b 54 24 ?? 4c 8b 44 24 ?? 41 8b 0c 08 8b 04 02 33 c1 ba 0c 00 00 00 8b c8}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((3 of ($x_1_*))) or
            ((1 of ($x_2_*) and 1 of ($x_1_*))) or
            ((2 of ($x_2_*))) or
            ((1 of ($x_3_*))) or
            (all of ($x*))
        )
}


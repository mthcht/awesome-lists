rule Worm_Win32_Oanum_A_2147575033_0
{
    meta:
        author = "defender2yara"
        detection_name = "Worm:Win32/Oanum.gen!A"
        threat_id = "2147575033"
        type = "Worm"
        platform = "Win32: Windows 32-bit platform"
        family = "Oanum"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "18"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {41 83 c0 04 c1 ea 02 3b ca}  //weight: 2, accuracy: High
        $x_2_2 = {51 51 56 57 68 00 00 04 00 e8 ?? ?? ff ff 8b f0 33 ff 3b f7 59 75 04 33 c0}  //weight: 2, accuracy: Low
        $x_3_3 = {74 d2 46 46 b8 00 05 00 00 3b 45 08 1b c0 f7 d8 03 f0 39 7d 08}  //weight: 3, accuracy: High
        $x_3_4 = {8a 14 08 03 c1 88 14 0f 47 40 8a 10 88 14 0f 47 40 4e 75 f6}  //weight: 3, accuracy: High
        $x_1_5 = "WINDOWS\\svch0st.exe" ascii //weight: 1
        $x_1_6 = "C:\\Progra~1\\Eset" ascii //weight: 1
        $x_1_7 = "\\Windows\\CurrentVersion\\Run" ascii //weight: 1
        $x_1_8 = "DOWNKILLLIST" ascii //weight: 1
        $x_1_9 = "DOWNLOADNUMS" ascii //weight: 1
        $x_1_10 = "killproc" ascii //weight: 1
        $x_1_11 = "ChkSum" ascii //weight: 1
        $x_1_12 = "ferefile" ascii //weight: 1
        $x_1_13 = "REMOVREGLIST" ascii //weight: 1
        $x_1_14 = "removreg" ascii //weight: 1
        $x_1_15 = "DOWNFILELIST" ascii //weight: 1
        $x_1_16 = "downfile" ascii //weight: 1
        $x_1_17 = "DOWNMAINLIST" ascii //weight: 1
        $x_1_18 = "mainfile" ascii //weight: 1
        $x_1_19 = "\\explorer.exe" ascii //weight: 1
        $x_1_20 = "_fere_" ascii //weight: 1
        $x_1_21 = "/config." ascii //weight: 1
        $x_1_22 = "ravtask" ascii //weight: 1
        $x_1_23 = "TerminateProcess" ascii //weight: 1
        $x_1_24 = "OpenProcess" ascii //weight: 1
        $x_1_25 = "CreateRemoteThread" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((18 of ($x_1_*))) or
            ((1 of ($x_2_*) and 16 of ($x_1_*))) or
            ((2 of ($x_2_*) and 14 of ($x_1_*))) or
            ((1 of ($x_3_*) and 15 of ($x_1_*))) or
            ((1 of ($x_3_*) and 1 of ($x_2_*) and 13 of ($x_1_*))) or
            ((1 of ($x_3_*) and 2 of ($x_2_*) and 11 of ($x_1_*))) or
            ((2 of ($x_3_*) and 12 of ($x_1_*))) or
            ((2 of ($x_3_*) and 1 of ($x_2_*) and 10 of ($x_1_*))) or
            ((2 of ($x_3_*) and 2 of ($x_2_*) and 8 of ($x_1_*))) or
            (all of ($x*))
        )
}


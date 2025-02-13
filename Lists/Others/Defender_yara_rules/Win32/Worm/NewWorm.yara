rule Worm_Win32_NewWorm_2147555607_0
{
    meta:
        author = "defender2yara"
        detection_name = "Worm:Win32/NewWorm"
        threat_id = "2147555607"
        type = "Worm"
        platform = "Win32: Windows 32-bit platform"
        family = "NewWorm"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "16"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "RegisterServiceProcess" ascii //weight: 1
        $x_1_2 = "Software\\Microsoft\\Windows\\CurrentVersion\\RunServices" ascii //weight: 1
        $x_2_3 = "SYSTEM\\CurrentControlSet\\Control\\Lsa" ascii //weight: 2
        $x_3_4 = "dcom135" ascii //weight: 3
        $x_3_5 = "ddos.syn" ascii //weight: 3
        $x_3_6 = "ddos.ack" ascii //weight: 3
        $x_3_7 = "ddos.random" ascii //weight: 3
        $x_4_8 = " Exploiting IP: %s." ascii //weight: 4
        $x_1_9 = "DRIVER={SQL Server};SERVER=%s,%d;UID=%s;PWD=%s;%s" ascii //weight: 1
        $x_1_10 = "nwncdkey.ini" ascii //weight: 1
        $x_1_11 = "Admin$\\system32" ascii //weight: 1
        $x_1_12 = "c$\\windows\\system32" ascii //weight: 1
        $x_1_13 = "c$\\winnt\\system32" ascii //weight: 1
        $x_1_14 = "%s\\ipc$" ascii //weight: 1
        $x_1_15 = "LANMAN2.1" ascii //weight: 1
        $x_1_16 = "\\\\%s\\pipe\\epmapper" ascii //weight: 1
        $x_1_17 = "Win2k Advanced Server [SP4]       netrap.dll" ascii //weight: 1
        $x_1_18 = "Win2k Professional    [universal] netrap.dll" ascii //weight: 1
        $x_1_19 = "WinXP Professional    [universal] lsass.exe " ascii //weight: 1
        $x_1_20 = "tftp -i %s get %s" ascii //weight: 1
        $x_1_21 = "EXEC master..xp_cmdshell '%s'" ascii //weight: 1
        $x_1_22 = {57 00 69 00 6e 00 64 00 6f 00 77 00 73 00 20 00 32 00 30 00 30 00 30 00 20 00 32 00 31 00 39 00 35}  //weight: 1, accuracy: High
        $x_1_23 = {57 00 69 00 6e 00 64 00 6f 00 77 00 73 00 20 00 32 00 30 00 30 00 30 00 20 00 35 00 2e 00 30}  //weight: 1, accuracy: High
        $x_1_24 = {5c 00 6c 00 73 00 61 00 72 00 70 00 63}  //weight: 1, accuracy: High
        $x_1_25 = {67 00 57 00 69 00 6e 00 64 00 6f 00 77 00 73 00 20 00 32 00 30 00 30 00 30 00 20 00 32 00 31 00 39 00 35}  //weight: 1, accuracy: High
        $x_1_26 = {5c 00 5c 00 31 00 39 00 32 00 2e 00 31 00 36 00 38 00 2e 00 31 00 2e 00 32 00 31 00 30 00 5c 00 49 00 50 00 43 00 24}  //weight: 1, accuracy: High
        $x_1_27 = {5c 00 43 00 24 00 5c 00 31 00 32 00 33 00 34 00 35 00 36 00 31 00 31 00 31 00 31 00 31 00 31 00 31 00 31 00 31 00 31 00 31 00 31 00 31 00 31 00 31 00 2e 00 64 00 6f 00 63}  //weight: 1, accuracy: High
        $x_1_28 = {5c 00 49 00 50 00 43 00 24}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((16 of ($x_1_*))) or
            ((1 of ($x_2_*) and 14 of ($x_1_*))) or
            ((1 of ($x_3_*) and 13 of ($x_1_*))) or
            ((1 of ($x_3_*) and 1 of ($x_2_*) and 11 of ($x_1_*))) or
            ((2 of ($x_3_*) and 10 of ($x_1_*))) or
            ((2 of ($x_3_*) and 1 of ($x_2_*) and 8 of ($x_1_*))) or
            ((3 of ($x_3_*) and 7 of ($x_1_*))) or
            ((3 of ($x_3_*) and 1 of ($x_2_*) and 5 of ($x_1_*))) or
            ((4 of ($x_3_*) and 4 of ($x_1_*))) or
            ((4 of ($x_3_*) and 1 of ($x_2_*) and 2 of ($x_1_*))) or
            ((1 of ($x_4_*) and 12 of ($x_1_*))) or
            ((1 of ($x_4_*) and 1 of ($x_2_*) and 10 of ($x_1_*))) or
            ((1 of ($x_4_*) and 1 of ($x_3_*) and 9 of ($x_1_*))) or
            ((1 of ($x_4_*) and 1 of ($x_3_*) and 1 of ($x_2_*) and 7 of ($x_1_*))) or
            ((1 of ($x_4_*) and 2 of ($x_3_*) and 6 of ($x_1_*))) or
            ((1 of ($x_4_*) and 2 of ($x_3_*) and 1 of ($x_2_*) and 4 of ($x_1_*))) or
            ((1 of ($x_4_*) and 3 of ($x_3_*) and 3 of ($x_1_*))) or
            ((1 of ($x_4_*) and 3 of ($x_3_*) and 1 of ($x_2_*) and 1 of ($x_1_*))) or
            ((1 of ($x_4_*) and 4 of ($x_3_*))) or
            (all of ($x*))
        )
}


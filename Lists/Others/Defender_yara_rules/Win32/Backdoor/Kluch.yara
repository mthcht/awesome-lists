rule Backdoor_Win32_Kluch_A_2147682464_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Kluch.A"
        threat_id = "2147682464"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Kluch"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "WLEventStartShell" ascii //weight: 1
        $x_1_2 = "logon is StartShellThread!!!" ascii //weight: 1
        $x_1_3 = "GUID=2f4b375b9odqejl5fuza45&LV=20077&V=%x&HASH=" ascii //weight: 1
        $x_1_4 = {47 6c 6f 62 61 6c 5c 46 32 42 41 46 32 36 38 45 45 46 46 44 44 00}  //weight: 1, accuracy: High
        $x_1_5 = "DectCmdRun....=%d" ascii //weight: 1
        $x_2_6 = {c6 45 fa 7c c6 45 fb bf c6 45 fc 4f c6 45 fd 7a c6 45 fe 6e c6 45 ff 8f f6 c3 07 74 03 43 eb f8 8d 7b 04 57}  //weight: 2, accuracy: High
        $x_1_7 = "nStartType=%d,szBkDllInstall=%s" ascii //weight: 1
        $x_1_8 = "0045322cfa.tmp" ascii //weight: 1
        $x_1_9 = "pInfo-lpszProxy1=%s" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((5 of ($x_1_*))) or
            ((1 of ($x_2_*) and 3 of ($x_1_*))) or
            (all of ($x*))
        )
}


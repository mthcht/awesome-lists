rule Worm_Win32_Locksky_A_2147593502_0
{
    meta:
        author = "defender2yara"
        detection_name = "Worm:Win32/Locksky.gen!A"
        threat_id = "2147593502"
        type = "Worm"
        platform = "Win32: Windows 32-bit platform"
        family = "Locksky"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "230"
        strings_accuracy = "High"
    strings:
        $x_100_1 = "zalupa" ascii //weight: 100
        $x_25_2 = "dwMagic: %X" ascii //weight: 25
        $x_25_3 = "rwx------ 1 user group" ascii //weight: 25
        $x_25_4 = "drwx------ 1 user group" ascii //weight: 25
        $x_25_5 = "Host:" ascii //weight: 25
        $x_25_6 = "Proxy-Conn" ascii //weight: 25
        $x_25_7 = "Server: %s, Obj: %s" ascii //weight: 25
        $x_10_8 = "UNLINK" ascii //weight: 10
        $x_10_9 = "LINK" ascii //weight: 10
        $x_10_10 = "POST" ascii //weight: 10
        $x_5_11 = "WinExec" ascii //weight: 5
        $x_5_12 = "NtOpenProcess" ascii //weight: 5
        $x_5_13 = "WriteProcessMemory" ascii //weight: 5
        $x_5_14 = "NtFreeVirtualMemory" ascii //weight: 5
        $x_5_15 = "RasEnumConnectionsA" ascii //weight: 5
        $x_5_16 = "NtQuerySystemInformation" ascii //weight: 5
        $x_5_17 = "NtAllocateVirtualMemory" ascii //weight: 5
        $x_1_18 = "netfilter.dll" ascii //weight: 1
        $x_1_19 = "f@gdiplus.dll" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_100_*) and 3 of ($x_25_*) and 2 of ($x_10_*) and 7 of ($x_5_*))) or
            ((1 of ($x_100_*) and 3 of ($x_25_*) and 3 of ($x_10_*) and 5 of ($x_5_*))) or
            ((1 of ($x_100_*) and 4 of ($x_25_*) and 6 of ($x_5_*))) or
            ((1 of ($x_100_*) and 4 of ($x_25_*) and 1 of ($x_10_*) and 4 of ($x_5_*))) or
            ((1 of ($x_100_*) and 4 of ($x_25_*) and 2 of ($x_10_*) and 2 of ($x_5_*))) or
            ((1 of ($x_100_*) and 4 of ($x_25_*) and 3 of ($x_10_*))) or
            ((1 of ($x_100_*) and 5 of ($x_25_*) and 1 of ($x_5_*))) or
            ((1 of ($x_100_*) and 5 of ($x_25_*) and 1 of ($x_10_*))) or
            ((1 of ($x_100_*) and 6 of ($x_25_*))) or
            (all of ($x*))
        )
}

rule Worm_Win32_Locksky_B_2147642944_0
{
    meta:
        author = "defender2yara"
        detection_name = "Worm:Win32/Locksky.gen!B"
        threat_id = "2147642944"
        type = "Worm"
        platform = "Win32: Windows 32-bit platform"
        family = "Locksky"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_4_1 = "Global\\{DD3B7FA8-3BE8-490f-8E9D-0036CE753679}" wide //weight: 4
        $x_3_2 = "mailer fail log ,hardware id: %lu,instcat version: %lu.%lu" ascii //weight: 3
        $x_3_3 = "/log2.php?hid=%lu" ascii //weight: 3
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


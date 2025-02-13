rule TrojanDownloader_Win32_Dkbits_2147575093_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Dkbits"
        threat_id = "2147575093"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Dkbits"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "11"
        strings_accuracy = "Low"
    strings:
        $x_3_1 = {31 32 37 2e 30 2e 30 2e 33 [0-16] 2e 63 6f 6d}  //weight: 3, accuracy: Low
        $x_2_2 = "drivers\\etc\\hosts" ascii //weight: 2
        $x_1_3 = "iframedollars.biz" ascii //weight: 1
        $x_1_4 = "dkprogs" ascii //weight: 1
        $x_1_5 = "dktibs.exe" ascii //weight: 1
        $x_1_6 = "C:\\WINDOWS\\SYSTEM32\\systime.exe" ascii //weight: 1
        $x_1_7 = "exploit.exe" ascii //weight: 1
        $x_1_8 = "fucker.exe" ascii //weight: 1
        $x_1_9 = "dladv" ascii //weight: 1
        $x_1_10 = "mstasks" ascii //weight: 1
        $x_1_11 = "CreateToolhelp32Snapshot" ascii //weight: 1
        $x_1_12 = "InternetOpen" ascii //weight: 1
        $x_1_13 = "TerminateProcess" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((11 of ($x_1_*))) or
            ((1 of ($x_2_*) and 9 of ($x_1_*))) or
            ((1 of ($x_3_*) and 8 of ($x_1_*))) or
            ((1 of ($x_3_*) and 1 of ($x_2_*) and 6 of ($x_1_*))) or
            (all of ($x*))
        )
}


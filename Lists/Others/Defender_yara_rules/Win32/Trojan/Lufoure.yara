rule Trojan_Win32_Lufoure_A_2147574094_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Lufoure.gen!A"
        threat_id = "2147574094"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Lufoure"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "15"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "CurrentControlSet\\Control\\InitRegKey" ascii //weight: 1
        $x_1_2 = "InitRegKey\\geoinfo" ascii //weight: 1
        $x_1_3 = "Explorer\\Browser Helper Objects" ascii //weight: 1
        $x_2_4 = "regsvr32.exe -s" ascii //weight: 2
        $x_2_5 = "regsvr32.exe -u -s" ascii //weight: 2
        $x_1_6 = "alwaysoff" ascii //weight: 1
        $x_1_7 = "boot.ini" ascii //weight: 1
        $x_1_8 = "initNotAlive" ascii //weight: 1
        $x_3_9 = "{1E6CE4CD-161B-4847-B8BF-" ascii //weight: 3
        $x_2_10 = "count.php?user=" ascii //weight: 2
        $x_1_11 = "@echo off" ascii //weight: 1
        $x_2_12 = ":delfile" ascii //weight: 2
        $x_1_13 = "del %1" ascii //weight: 1
        $x_2_14 = "if exist %1 goto delfile" ascii //weight: 2
        $x_1_15 = "iexplore[1].exe" ascii //weight: 1
        $x_1_16 = "sox1.exe" ascii //weight: 1
        $x_1_17 = "CreateToolhelp32Snapshot" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_2_*) and 11 of ($x_1_*))) or
            ((3 of ($x_2_*) and 9 of ($x_1_*))) or
            ((4 of ($x_2_*) and 7 of ($x_1_*))) or
            ((5 of ($x_2_*) and 5 of ($x_1_*))) or
            ((1 of ($x_3_*) and 1 of ($x_2_*) and 10 of ($x_1_*))) or
            ((1 of ($x_3_*) and 2 of ($x_2_*) and 8 of ($x_1_*))) or
            ((1 of ($x_3_*) and 3 of ($x_2_*) and 6 of ($x_1_*))) or
            ((1 of ($x_3_*) and 4 of ($x_2_*) and 4 of ($x_1_*))) or
            ((1 of ($x_3_*) and 5 of ($x_2_*) and 2 of ($x_1_*))) or
            (all of ($x*))
        )
}


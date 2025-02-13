rule Backdoor_Win32_Tomyjery_A_2147724450_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Tomyjery.A"
        threat_id = "2147724450"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Tomyjery"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_3_1 = "Tom&Jerry@14here" ascii //weight: 3
        $x_2_2 = "%s\\HTTPDLL.dll" ascii //weight: 2
        $x_2_3 = "%s\\converts.dll" ascii //weight: 2
        $x_2_4 = "%s\\logs\\logs-%" ascii //weight: 2
        $x_1_5 = "HostName=%s" ascii //weight: 1
        $x_1_6 = "Decodes=%d" ascii //weight: 1
        $x_1_7 = "DownloadURLThread failed in WorkerThread" ascii //weight: 1
        $x_1_8 = "ExcuteCmdThread failed in WorkerThread" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_2_*) and 3 of ($x_1_*))) or
            ((3 of ($x_2_*) and 1 of ($x_1_*))) or
            ((1 of ($x_3_*) and 4 of ($x_1_*))) or
            ((1 of ($x_3_*) and 1 of ($x_2_*) and 2 of ($x_1_*))) or
            ((1 of ($x_3_*) and 2 of ($x_2_*))) or
            (all of ($x*))
        )
}


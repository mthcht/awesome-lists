rule TrojanProxy_Win32_Diskmaster_2147583206_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanProxy:Win32/Diskmaster"
        threat_id = "2147583206"
        type = "TrojanProxy"
        platform = "Win32: Windows 32-bit platform"
        family = "Diskmaster"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Content-Disposition: form-data; name=\"tracelog\"" ascii //weight: 1
        $x_1_2 = "Content-Disposition: form-data; name=\"emails\"" ascii //weight: 1
        $x_1_3 = "152.2.21.1" ascii //weight: 1
        $x_1_4 = "209.81.7.11" ascii //weight: 1
        $x_1_5 = "http://%d.%d.%d.%d:%d/" ascii //weight: 1
        $x_1_6 = "!SMTP_START_2" ascii //weight: 1
        $x_1_7 = "http://%d.%d.%d.%d:%d/%d/%d/%d/%d/%d/%d/" ascii //weight: 1
        $x_1_8 = "X-Good: %d:%s" ascii //weight: 1
        $x_1_9 = "!SMTP_SEND" ascii //weight: 1
        $x_1_10 = "!READ_ERROR" ascii //weight: 1
        $x_1_11 = "Floppy Master" ascii //weight: 1
        $x_1_12 = "THREADS=" ascii //weight: 1
        $x_1_13 = "%H:%M:%S" ascii //weight: 1
        $x_1_14 = "X-Confirm: %d:%s" ascii //weight: 1
        $x_1_15 = "\\CurrentVersion\\Internet Settings" ascii //weight: 1
        $x_1_16 = "Mozilla/%d.%d (compatible; MSIE %d.%d; Windows NT %d.%d)" ascii //weight: 1
        $x_3_17 = {3b 50 a3 3c 8b 45 fc 83 c0 01 89 45 fc 8b 4d fc c7 04 8d}  //weight: 3, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((10 of ($x_1_*))) or
            ((1 of ($x_3_*) and 7 of ($x_1_*))) or
            (all of ($x*))
        )
}


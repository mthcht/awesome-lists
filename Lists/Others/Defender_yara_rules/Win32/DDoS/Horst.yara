rule DDoS_Win32_Horst_AK_2147608185_0
{
    meta:
        author = "defender2yara"
        detection_name = "DDoS:Win32/Horst.AK"
        threat_id = "2147608185"
        type = "DDoS"
        platform = "Win32: Windows 32-bit platform"
        family = "Horst"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "21"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {31 32 37 2e 30 2e 30 2e 31 09 73 79 6d 61 6e 74 65 63 2e 63 6f 6d 0d 0a 31 32 37 2e 30 2e 30 2e 31 09 77 77 77 2e 73 6f 70 68 6f 73 2e 63 6f 6d 0d 0a 31 32 37 2e 30 2e 30 2e 31 09 73 6f 70 68 6f 73 2e 63 6f 6d 0d 0a 31 32 37 2e 30 2e 30 2e 31 09 77 77 77 2e 6d 63 61 66 65 65 2e 63 6f 6d 0d 0a 31 32 37 2e 30 2e 30 2e 31 09 6d 63 61 66 65 65 2e 63 6f 6d 0d 0a}  //weight: 10, accuracy: High
        $x_10_2 = {61 6e 79 20 73 65 72 76 69 63 65 73 20 74 68 61 74 20 65 78 70 6c 69 63 69 74 6c 79 20 64 65 70 65 6e 64 20 6f 6e 20 69 74 20 77 69 6c 6c 20 66 61 69 6c 20 74 6f 20 73 74 61 72 74 2e [0-144] 32 31 36 2e 31 30 39 2e 31 32 37 2e 36 30 00 00 47 65 74 46 72 69 65 6e 64 6c 79 49 66 49 6e 64 65 78}  //weight: 10, accuracy: Low
        $x_1_3 = "Network Client Monitor" ascii //weight: 1
        $x_1_4 = "navapsvc" ascii //weight: 1
        $x_1_5 = "Symantec Core LC" ascii //weight: 1
        $x_1_6 = "SAVScan " ascii //weight: 1
        $x_1_7 = "kavsvc " ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_10_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}


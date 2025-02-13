rule Worm_Win32_Cissi_2147582927_0
{
    meta:
        author = "defender2yara"
        detection_name = "Worm:Win32/Cissi.gen"
        threat_id = "2147582927"
        type = "Worm"
        platform = "Win32: Windows 32-bit platform"
        family = "Cissi"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "63.251.216.11" ascii //weight: 1
        $x_1_2 = "152.163.159.232" ascii //weight: 1
        $x_1_3 = "149.174.211.8" ascii //weight: 1
        $x_1_4 = "64.12.51.132" ascii //weight: 1
        $x_1_5 = "216.109.116.17" ascii //weight: 1
        $x_1_6 = "cissi@yahoo.com" ascii //weight: 1
        $x_1_7 = "Poem_collection.pif" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


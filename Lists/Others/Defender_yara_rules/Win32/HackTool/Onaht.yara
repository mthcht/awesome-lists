rule HackTool_Win32_Onaht_A_2147685081_0
{
    meta:
        author = "defender2yara"
        detection_name = "HackTool:Win32/Onaht.A"
        threat_id = "2147685081"
        type = "HackTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Onaht"
        severity = "High"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "[ONHAT] CONNECTS (%d.%d.%d.%d, %d.%d.%d.%d, %d)" ascii //weight: 1
        $x_1_2 = "[ONHAT] ACCEPTS (%d.%d.%d.%d, %d)" ascii //weight: 1
        $x_1_3 = "[ONHAT] LISTENS (%d.%d.%d.%d, %d)" ascii //weight: 1
        $x_2_4 = "ONTAH.EXE -h FOR HELP INFORMATION" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (
            ((3 of ($x_1_*))) or
            ((1 of ($x_2_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}


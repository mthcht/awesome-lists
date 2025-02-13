rule HackTool_Win32_Vrsten_A_2147723368_0
{
    meta:
        author = "defender2yara"
        detection_name = "HackTool:Win32/Vrsten.A!dha"
        threat_id = "2147723368"
        type = "HackTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Vrsten"
        severity = "High"
        info = "dha: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "100"
        strings_accuracy = "Low"
    strings:
        $x_20_1 = "%s\\SysWOW64\\rundll32.exe" wide //weight: 20
        $x_20_2 = "%s\\system32\\rundll32.exe" wide //weight: 20
        $x_30_3 = "Process %d Created" ascii //weight: 30
        $x_10_4 = "slbdnsn1" wide //weight: 10
        $x_10_5 = "slbdnsk1" wide //weight: 10
        $x_10_6 = {73 6c 62 64 6e 73 (6e|6b) 31}  //weight: 10, accuracy: Low
        $x_10_7 = {73 6c 62 64 6e 73 20 (4e|4b) 31}  //weight: 10, accuracy: Low
        $x_10_8 = "slbsmbn1" wide //weight: 10
        $x_10_9 = "slbsmbk1" wide //weight: 10
        $x_10_10 = {73 6c 62 73 6d 62 (6e|6b) 31}  //weight: 10, accuracy: Low
        $x_10_11 = {73 6c 62 73 6d 62 20 (4e|4b) 31}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_20_*) and 8 of ($x_10_*))) or
            ((2 of ($x_20_*) and 6 of ($x_10_*))) or
            ((1 of ($x_30_*) and 7 of ($x_10_*))) or
            ((1 of ($x_30_*) and 1 of ($x_20_*) and 5 of ($x_10_*))) or
            ((1 of ($x_30_*) and 2 of ($x_20_*) and 3 of ($x_10_*))) or
            (all of ($x*))
        )
}


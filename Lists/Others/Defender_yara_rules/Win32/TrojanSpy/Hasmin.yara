rule TrojanSpy_Win32_Hasmin_A_2147647346_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:Win32/Hasmin.A"
        threat_id = "2147647346"
        type = "TrojanSpy"
        platform = "Win32: Windows 32-bit platform"
        family = "Hasmin"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_3_1 = "L3NlY3VyaXR5Lm1peG11c2ljYXMubmV0L" ascii //weight: 3
        $x_3_2 = "L2FsYmF0cm96LXJlbC9wL2FjY2Vzcy5w" ascii //weight: 3
        $x_1_3 = "XE1vemlsbGFcRmlyZWZveFxQcm9maWxlcw==" wide //weight: 1
        $x_1_4 = "dXNlcl9wcmVmKCJuZXR3b3JrLnByb3h5LmF1dG9jb25maWdfdXJs" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_3_*))) or
            (all of ($x*))
        )
}


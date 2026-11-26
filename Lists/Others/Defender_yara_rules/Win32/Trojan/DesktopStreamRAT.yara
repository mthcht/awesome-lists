rule Trojan_Win32_DesktopStreamRAT_2147982853_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/DesktopStreamRAT!atmn"
        threat_id = "2147982853"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "DesktopStreamRAT"
        severity = "Critical"
        info = "atmn: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_3_1 = "Self-donor direct module target selected:" wide //weight: 3
        $x_3_2 = "PayloadKeepAlive skipped: server URL is empty" wide //weight: 3
        $x_2_3 = "LOLD_CFG_V1" ascii //weight: 2
        $x_2_4 = "Container placeholder exited without normal loader workflow" wide //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


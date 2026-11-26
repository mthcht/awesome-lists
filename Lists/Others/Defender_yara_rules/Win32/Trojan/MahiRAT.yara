rule Trojan_Win32_MahiRAT_2147982850_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/MahiRAT!atmn"
        threat_id = "2147982850"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "MahiRAT"
        severity = "Critical"
        info = "atmn: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "18"
        strings_accuracy = "High"
    strings:
        $x_3_1 = "MahiRatKey0123456789ABCDEF012300" ascii //weight: 3
        $x_3_2 = "MahiRatIV0123456" ascii //weight: 3
        $x_3_3 = "MahiSvc_Main_Local_v2" ascii //weight: 3
        $x_2_4 = "mahi_agent.log" ascii //weight: 2
        $x_2_5 = "mh_web.db" ascii //weight: 2
        $x_2_6 = "] Cle maitresse introuvable (DPAPI)" ascii //weight: 2
        $x_2_7 = "schtasks /delete /tn \"HostUpdate\" /f >nul 2>&1" ascii //weight: 2
        $x_1_8 = "mh_scr.jpg" ascii //weight: 1
        $x_1_9 = "fmh_cam.jpg" ascii //weight: 1
        $x_1_10 = "screen_start" ascii //weight: 1
        $x_1_11 = "mine_status" ascii //weight: 1
        $x_1_12 = "SELECT origin_url,username_value,password_value FROM logins" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_3_*) and 4 of ($x_2_*) and 4 of ($x_1_*))) or
            ((3 of ($x_3_*) and 2 of ($x_2_*) and 5 of ($x_1_*))) or
            ((3 of ($x_3_*) and 3 of ($x_2_*) and 3 of ($x_1_*))) or
            ((3 of ($x_3_*) and 4 of ($x_2_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}


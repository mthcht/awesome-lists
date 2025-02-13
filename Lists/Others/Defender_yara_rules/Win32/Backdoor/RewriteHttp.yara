rule Backdoor_Win32_RewriteHttp_A_2147831177_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/RewriteHttp.A"
        threat_id = "2147831177"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "RewriteHttp"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "54"
        strings_accuracy = "High"
    strings:
        $x_50_1 = "CHttpModule" ascii //weight: 50
        $x_1_2 = "CMD|" ascii //weight: 1
        $x_1_3 = "WRF|" ascii //weight: 1
        $x_1_4 = "PIN|" ascii //weight: 1
        $x_1_5 = "INJ|" ascii //weight: 1
        $x_1_6 = "DMP|" ascii //weight: 1
        $x_1_7 = "Query=" ascii //weight: 1
        $x_1_8 = "EB:%d!" ascii //weight: 1
        $x_1_9 = "CreateProcessA" ascii //weight: 1
        $x_1_10 = "%02d/%02d/%04d %02d:%02d:%02d | %s" ascii //weight: 1
        $x_1_11 = "cmd.exe" ascii //weight: 1
        $x_1_12 = "/c %s" ascii //weight: 1
        $x_1_13 = "credwiz.exe" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_50_*) and 4 of ($x_1_*))) or
            (all of ($x*))
        )
}


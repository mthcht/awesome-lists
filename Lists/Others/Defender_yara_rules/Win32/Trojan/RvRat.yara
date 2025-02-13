rule Trojan_Win32_RvRat_A_2147730262_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/RvRat.A!MTB"
        threat_id = "2147730262"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "RvRat"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "RevCode-" wide //weight: 1
        $x_1_2 = "&task_id=" wide //weight: 1
        $x_1_3 = "Goto Delfile" wide //weight: 1
        $x_1_4 = ":Delfile" wide //weight: 1
        $x_1_5 = "\\Software\\Microsoft\\Windows\\CurrentVersion\\Run" wide //weight: 1
        $x_1_6 = "revcodestamp592" wide //weight: 1
        $x_1_7 = "send_screenstream_start" wide //weight: 1
        $x_1_8 = "send_keylog_stream_data" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


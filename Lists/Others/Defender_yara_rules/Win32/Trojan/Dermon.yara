rule Trojan_Win32_Dermon_A_2147593255_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Dermon.A"
        threat_id = "2147593255"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Dermon"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "64.237.57.119/wmex/filtr.txt" ascii //weight: 1
        $x_1_2 = "64.237.57.119/wmex/iplog.txt" ascii //weight: 1
        $x_1_3 = "64.237.57.119/wmex/pslog.txt" ascii //weight: 1
        $x_2_4 = "Loaded new addr: %s" ascii //weight: 2
        $x_2_5 = "Begin load url... String: %s, Host: %s Script: %s" ascii //weight: 2
        $x_1_6 = "c:\\logi.log" ascii //weight: 1
        $x_1_7 = "Software\\Auogu\\" ascii //weight: 1
        $x_1_8 = "/%s/l.php?d=%s&a=%s&c=%s" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 5 of ($x_1_*))) or
            ((2 of ($x_2_*) and 3 of ($x_1_*))) or
            (all of ($x*))
        )
}


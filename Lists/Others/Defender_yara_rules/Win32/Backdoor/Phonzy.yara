rule Backdoor_Win32_Phonzy_A_2147912716_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Phonzy.A"
        threat_id = "2147912716"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Phonzy"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "svchost.exe" ascii //weight: 1
        $x_1_2 = "PLINK_PROTOCOL" ascii //weight: 1
        $x_1_3 = "Plink: command-line connection utility" ascii //weight: 1
        $x_1_4 = "LVMLOGF" ascii //weight: 1
        $x_1_5 = "nologin@www.gesucht.net" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


rule Backdoor_Win32_Miweroot_A_2147679393_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Miweroot.A"
        threat_id = "2147679393"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Miweroot"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "s://+:443" ascii //weight: 1
        $x_1_2 = "HttpAddUrl failed with %lu" ascii //weight: 1
        $x_1_3 = "er file is transfering,wait and retry." ascii //weight: 1
        $x_1_4 = "en on: %s,wait connect..." ascii //weight: 1
        $x_1_5 = "%s(%u.%u.%u.%u) connected." ascii //weight: 1
        $x_1_6 = "1.3.6.1.5.5.7.3.1" ascii //weight: 1
        $x_1_7 = "%d %sFile/" ascii //weight: 1
        $x_1_8 = "DoFileTransfer:" ascii //weight: 1
        $x_1_9 = "er Timeout,File %s failed!" ascii //weight: 1
        $x_1_10 = "le %s successed!" ascii //weight: 1
        $x_1_11 = "%02d%02d%02d%02d%02d%02d.txt" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (7 of ($x*))
}


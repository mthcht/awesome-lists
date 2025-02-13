rule Trojan_Win32_Ghopog_A_2147638318_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Ghopog.A"
        threat_id = "2147638318"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Ghopog"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "backdoor.dll" ascii //weight: 1
        $x_1_2 = "\\Update\\ver.list" ascii //weight: 1
        $x_1_3 = "%s?TG=%s&Mac=%s&Ver=%s&Jc=%d&Yp=%s&KEY=%d&CP=%s" ascii //weight: 1
        $x_1_4 = {65 57 56 6c 59 53 73 2b 50 [0-100] 35 53 66 6d 52 2f 5a 54 39 77 59 6d 45 52}  //weight: 1, accuracy: Low
        $x_1_5 = {72 61 76 6d 6f 6e 64 2e 65 78 65 ?? 51 51 2e 65 78 65 ?? ?? 70 66 77 2e 65 78 65 ?? 6c 73 61 73 73 2e 65 78 65}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


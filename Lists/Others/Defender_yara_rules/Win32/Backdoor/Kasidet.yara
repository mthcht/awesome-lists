rule Backdoor_Win32_Kasidet_C_2147694397_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Kasidet.C"
        threat_id = "2147694397"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Kasidet"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "botkiller" ascii //weight: 1
        $x_1_2 = "dwflood" ascii //weight: 1
        $x_2_3 = "cmd=1&uid=%s&os=%s&av=%s&version=%s&quality=%i" wide //weight: 2
        $x_10_4 = "N3NNetwork" ascii //weight: 10
        $x_1_5 = {69 c0 e8 03 00 00 6b c0 3c 89 85 ?? ?? ?? ?? 83 bd ?? ?? ?? ?? 00 7f ?? c7 85 ?? ?? ?? ?? 60 ea 00 00 81 bd ?? ?? ?? ?? 80 ee 36 00 7e ?? c7 85 ?? ?? ?? ?? 80 ee 36 00}  //weight: 1, accuracy: Low
        $x_1_6 = {69 f6 60 ea 00 00 85 f6 7f ?? be 60 ea 00 00 eb ?? 81 fe 80 ee 36 00 7e ?? be 80 ee 36 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_1_*))) or
            ((1 of ($x_2_*))) or
            ((1 of ($x_10_*))) or
            (all of ($x*))
        )
}


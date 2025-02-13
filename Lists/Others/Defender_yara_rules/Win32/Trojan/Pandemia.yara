rule Trojan_Win32_Pandemia_A_2147740640_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Pandemia.A!dha"
        threat_id = "2147740640"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Pandemia"
        severity = "Critical"
        info = "dha: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Can't stop service : mouclass" ascii //weight: 1
        $x_1_2 = "delete folder exception : " ascii //weight: 1
        $x_1_3 = "delete file exception : " ascii //weight: 1
        $x_1_4 = "App Start Work !!!!" ascii //weight: 1
        $x_1_5 = "Start Time Params : " ascii //weight: 1
        $x_1_6 = "Read Timestamp : " ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (4 of ($x*))
}


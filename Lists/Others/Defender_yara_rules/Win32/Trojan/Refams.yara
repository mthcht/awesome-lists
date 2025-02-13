rule Trojan_Win32_Refams_A_2147611814_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Refams.A"
        threat_id = "2147611814"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Refams"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "30"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "@*\\AE:\\RE9FA3~1\\BUG_1_~1\\XXXXXX~1.VBP" wide //weight: 10
        $x_10_2 = "\\dllcache\\Download_File\\Download_File\\Download_File\\Download_File\\Download_File" wide //weight: 10
        $x_10_3 = "Can You this is Program File Remove" ascii //weight: 10
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


rule Backdoor_Win32_Mailie_A_2147721413_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Mailie.A"
        threat_id = "2147721413"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Mailie"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "//%s/webmail.php?id=%s" ascii //weight: 1
        $x_1_2 = "g00g1e" ascii //weight: 1
        $x_1_3 = "9o0gl0" ascii //weight: 1
        $x_1_4 = "%s /C %s >>\"%s\" 2>&1" ascii //weight: 1
        $x_1_5 = "Explorer\\PhishingFilter" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


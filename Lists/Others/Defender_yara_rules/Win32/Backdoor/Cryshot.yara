rule Backdoor_Win32_Cryshot_A_2147710502_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Cryshot.A"
        threat_id = "2147710502"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Cryshot"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "12"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "takescreenshot::done screenshot in memory" ascii //weight: 1
        $x_1_2 = "main::failed to take screenshot" ascii //weight: 1
        $x_10_3 = ".nn-group.co/req" ascii //weight: 10
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


rule Backdoor_Win32_BlackShellRat_PAGF_2147929912_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/BlackShellRat.PAGF!MTB"
        threat_id = "2147929912"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "BlackShellRat"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_3_1 = "[B~l~a~c~k~S~h~e~l~l]" ascii //weight: 3
        $x_2_2 = "\\quickstart.exe" ascii //weight: 2
        $x_1_3 = "\\cmd.exe" ascii //weight: 1
        $x_1_4 = "Program Files\\Internet Explorer\\iexplore.exe" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


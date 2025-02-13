rule Backdoor_Win32_Saeeka_A_2147625065_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Saeeka.A"
        threat_id = "2147625065"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Saeeka"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Sa3eKa RAT Attacker        lll By HACKER85 lll" ascii //weight: 1
        $x_1_2 = "Remote Download/Execute" ascii //weight: 1
        $x_1_3 = "(hacker85.no-ip.biz)" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_Win32_Saeeka_B_2147652705_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Saeeka.B"
        threat_id = "2147652705"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Saeeka"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Sa3eka Toolz" ascii //weight: 1
        $x_1_2 = "\\s3ka.txt" wide //weight: 1
        $x_1_3 = "\\Hacked.bmp" wide //weight: 1
        $x_1_4 = "OPENVIRUS" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


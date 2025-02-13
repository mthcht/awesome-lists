rule Backdoor_Win32_RedaMan_A_2147744339_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/RedaMan.A"
        threat_id = "2147744339"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "RedaMan"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "vfoghjvvhtmwicsp" ascii //weight: 1
        $x_1_2 = "pnevdtqvbhbcrmegp" ascii //weight: 1
        $x_1_3 = "wudemedil" ascii //weight: 1
        $x_1_4 = "bncobjapi.dll" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


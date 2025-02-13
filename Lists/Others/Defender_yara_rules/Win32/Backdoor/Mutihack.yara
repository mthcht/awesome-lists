rule Backdoor_Win32_Mutihack_A_2147636928_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Mutihack.A"
        threat_id = "2147636928"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Mutihack"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_3_1 = "Global\\Muti%dHack" ascii //weight: 3
        $x_1_2 = "mutihack.dll" ascii //weight: 1
        $x_1_3 = "rundll32.exe %s, Startup %s" ascii //weight: 1
        $x_2_4 = "bbs.MutiHack.com" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 2 of ($x_1_*))) or
            ((1 of ($x_3_*) and 1 of ($x_1_*))) or
            ((1 of ($x_3_*) and 1 of ($x_2_*))) or
            (all of ($x*))
        )
}


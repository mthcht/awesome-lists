rule Backdoor_Win32_Payduse_A_2147709393_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Payduse.A!bit"
        threat_id = "2147709393"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Payduse"
        severity = "Critical"
        info = "bit: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "net1 user guest guest123!@#" ascii //weight: 2
        $x_1_2 = "taskkill /im sathc.exe /f" ascii //weight: 1
        $x_1_3 = "net1 user guest /active:yes" ascii //weight: 1
        $x_1_4 = "net1 localgroup administrators guest /add" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((3 of ($x_1_*))) or
            ((1 of ($x_2_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}


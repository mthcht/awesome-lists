rule Backdoor_Win32_Bexelets_A_2147683153_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Bexelets.A"
        threat_id = "2147683153"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Bexelets"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {07 45 78 65 63 75 74 65 08 54 42 6f 74 4b 69 6c 6c}  //weight: 2, accuracy: High
        $x_2_2 = {07 65 78 65 63 75 74 65 07 54 4f 6d 65 67 6c 65}  //weight: 2, accuracy: High
        $x_1_3 = "No passwords logged|" ascii //weight: 1
        $x_1_4 = "TTcpAtk" ascii //weight: 1
        $x_1_5 = "TUdpAtk" ascii //weight: 1
        $x_1_6 = "AddDNSSpoof" ascii //weight: 1
        $x_1_7 = "lld.llDeibS" ascii //weight: 1
        $x_1_8 = "BK.EXC." ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((4 of ($x_1_*))) or
            ((1 of ($x_2_*) and 2 of ($x_1_*))) or
            ((2 of ($x_2_*))) or
            (all of ($x*))
        )
}


rule Backdoor_Win32_Deppeels_A_2147696735_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Deppeels.A"
        threat_id = "2147696735"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Deppeels"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Remote computer will been sleepped for %d" ascii //weight: 1
        $x_1_2 = {66 75 63 6b 00}  //weight: 1, accuracy: High
        $x_1_3 = "InitBackDoor()" ascii //weight: 1
        $x_1_4 = "Dll has been deleted,recover it from memory!" ascii //weight: 1
        $x_1_5 = "Create Reverse Shell Thread begin" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}


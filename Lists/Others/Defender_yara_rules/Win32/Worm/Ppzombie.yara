rule Worm_Win32_Ppzombie_A_2147642695_0
{
    meta:
        author = "defender2yara"
        detection_name = "Worm:Win32/Ppzombie.A"
        threat_id = "2147642695"
        type = "Worm"
        platform = "Win32: Windows 32-bit platform"
        family = "Ppzombie"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Intelligent P2P Zombie" ascii //weight: 1
        $x_1_2 = {00 25 73 5c 41 44 4d 49 4e 24 00}  //weight: 1, accuracy: High
        $x_1_3 = "[--install] [--remove] [--log <name>]" ascii //weight: 1
        $x_1_4 = {00 25 73 5c 49 50 43 24 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


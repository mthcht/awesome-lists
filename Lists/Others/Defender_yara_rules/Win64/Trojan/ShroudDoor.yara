rule Trojan_Win64_ShroudDoor_AA_2147961345_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/ShroudDoor.AA!dha"
        threat_id = "2147961345"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "ShroudDoor"
        severity = "Critical"
        info = "dha: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "0 [[:graph:]]+" ascii //weight: 1
        $x_1_2 = "1 [[:graph:]]+" ascii //weight: 1
        $x_1_3 = "SELECT * FROM Win32_OperatingSystem" wide //weight: 1
        $x_1_4 = "ROOT\\CIMV2" wide //weight: 1
        $x_1_5 = {11 f8 90 45 3a 1d d0 11 89 1f 00 aa 00 4b 2e 24}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


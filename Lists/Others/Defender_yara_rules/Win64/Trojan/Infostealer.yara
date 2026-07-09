rule Trojan_Win64_Infostealer_NA_2147924596_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Infostealer.NA!MTB"
        threat_id = "2147924596"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Infostealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "C:\\Users\\Musquitao\\Desktop\\BR_2023\\LOADCPP2024\\LOAD_EXE\\x64\\Release\\LOAD_EXE.pdb" ascii //weight: 2
        $x_1_2 = "Musquitao" ascii //weight: 1
        $x_1_3 = "settings.dat" ascii //weight: 1
        $x_1_4 = "secxete 1" ascii //weight: 1
        $x_1_5 = "Anapolos 2" ascii //weight: 1
        $x_1_6 = "htzp://" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Infostealer_ABD_2147973273_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Infostealer.ABD!MTB"
        threat_id = "2147973273"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Infostealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_4_1 = {41 89 cd 41 83 cd 03 45 89 ef 41 83 e7 fe 41 89 ec 41 c1 ec 08 40 30 f5 40 0f b6 ed 45 33 24 aa 45 0f af fd 44 89 e5 45 21 dc 41 01 c4 41 69 c4 ?? ?? ?? ?? ff c0 41 89 c4 41 c1 ec 18 41 89 cd 44 21 d9 44 31 e1 41 c1 ef 08 41 c1 ed 08 45 33 2c 8a 41 30 f7 46 88 3c 0a}  //weight: 4, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


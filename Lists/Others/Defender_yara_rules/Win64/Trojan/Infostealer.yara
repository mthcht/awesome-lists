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


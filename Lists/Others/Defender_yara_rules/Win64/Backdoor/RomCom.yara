rule Backdoor_Win64_RomCom_A_2147851917_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win64/RomCom.A"
        threat_id = "2147851917"
        type = "Backdoor"
        platform = "Win64: Windows 64-bit platform"
        family = "RomCom"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "DRIVE_NO_ROOT_DIR - %s" ascii //weight: 1
        $x_1_2 = "SCREENSHOOTER uploaded to client" ascii //weight: 1
        $x_1_3 = "C:\\ProgramData\\worker.txt" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (2 of ($x*))
}

rule Backdoor_Win64_RomCom_B_2147851922_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win64/RomCom.B"
        threat_id = "2147851922"
        type = "Backdoor"
        platform = "Win64: Windows 64-bit platform"
        family = "RomCom"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {c1 e1 03 48 8b [0-6] 48 d3 ea 48 8b ca 0f b6 c9 33 c1}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


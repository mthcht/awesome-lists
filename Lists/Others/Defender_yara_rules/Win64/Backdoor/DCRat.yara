rule Backdoor_Win64_DCRat_GP_2147815757_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win64/DCRat.GP!MTB"
        threat_id = "2147815757"
        type = "Backdoor"
        platform = "Win64: Windows 64-bit platform"
        family = "DCRat"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "12"
        strings_accuracy = "High"
    strings:
        $x_10_1 = {0f b6 14 03 0f b6 4c 05 00 30 d1 88 0c 03 88 54 05 00 48 8d 48 01 48 89 c8 49 39 cf 75 e2}  //weight: 10, accuracy: High
        $x_1_2 = "pestilence.pdb" ascii //weight: 1
        $x_1_3 = "CreateMutex" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_Win64_DCRat_RHB_2147914344_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win64/DCRat.RHB!MTB"
        threat_id = "2147914344"
        type = "Backdoor"
        platform = "Win64: Windows 64-bit platform"
        family = "DCRat"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "DeadBot" ascii //weight: 1
        $x_1_2 = "Malware" ascii //weight: 1
        $x_1_3 = "NativeLoader" wide //weight: 1
        $x_2_4 = {50 45 00 00 64 86 06 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 0b 02 0e 27 00 46 00 00 00 0c 06 00 00 00 00 00 40 46}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


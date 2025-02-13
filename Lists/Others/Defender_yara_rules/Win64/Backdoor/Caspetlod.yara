rule Backdoor_Win64_Caspetlod_A_2147782298_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win64/Caspetlod.A!dha"
        threat_id = "2147782298"
        type = "Backdoor"
        platform = "Win64: Windows 64-bit platform"
        family = "Caspetlod"
        severity = "Critical"
        info = "dha: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {01 00 c7 44 24 38 48 31 c0 c3 ff 15}  //weight: 1, accuracy: High
        $x_1_2 = {45 74 77 45 76 65 6e 74 57 72 69 74 65 00 00 00 73 79 73 74 65 6d}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


rule Backdoor_Win64_ShadowWraith_A_2147951088_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win64/ShadowWraith.A!dha"
        threat_id = "2147951088"
        type = "Backdoor"
        platform = "Win64: Windows 64-bit platform"
        family = "ShadowWraith"
        severity = "Critical"
        info = "dha: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Started Main" wide //weight: 1
        $x_1_2 = "Created core" wide //weight: 1
        $x_1_3 = "Not registered" wide //weight: 1
        $x_1_4 = "Done initial tasks" wide //weight: 1
        $x_1_5 = "No need to init" wide //weight: 1
        $x_1_6 = "Running" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (5 of ($x*))
}


rule Backdoor_Win64_RogueClimb_A_2147967088_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win64/RogueClimb.A!dha"
        threat_id = "2147967088"
        type = "Backdoor"
        platform = "Win64: Windows 64-bit platform"
        family = "RogueClimb"
        severity = "Critical"
        info = "dha: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "tambur/internal/win.MakeKey" ascii //weight: 1
        $x_1_2 = "tambur/internal/win.GetUUID" ascii //weight: 1
        $x_1_3 = "tambur/internal/win.GetHostname" ascii //weight: 1
        $x_1_4 = "tambur/internal/win.EnableRDP" ascii //weight: 1
        $x_1_5 = "tambur/internal/win.GetSSH" ascii //weight: 1
        $x_1_6 = "tambur/internal/win.DestructTambur" ascii //weight: 1
        $x_1_7 = "tambur/internal/win.MakeTunnel" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (4 of ($x*))
}

rule Backdoor_Win64_RogueClimb_A_2147967088_1
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win64/RogueClimb.A!dha"
        threat_id = "2147967088"
        type = "Backdoor"
        platform = "Win64: Windows 64-bit platform"
        family = "RogueClimb"
        severity = "Critical"
        info = "dha: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "users\\public\\libraries\\tambur" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


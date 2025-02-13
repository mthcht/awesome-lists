rule VirTool_Win32_Ekocit_A_2147814859_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/Ekocit.A!MTB"
        threat_id = "2147814859"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Ekocit"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "amenzhinsky/go-memexec" ascii //weight: 1
        $x_1_2 = "go-memexec.(*Exec).Command" ascii //weight: 1
        $x_1_3 = "main.decrypt" ascii //weight: 1
        $x_1_4 = {50 a7 f4 51 53 65 41 7e c3 a4 17 1a 96 5e 27 3a cb 6b ab 3b f1 45 9d 1f ab 58 fa ac 93 03 e3 4b}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


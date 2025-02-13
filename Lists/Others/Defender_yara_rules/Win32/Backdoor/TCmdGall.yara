rule Backdoor_Win32_TCmdGall_A_2147796129_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/TCmdGall.A!dha"
        threat_id = "2147796129"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "TCmdGall"
        severity = "Critical"
        info = "dha: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "CreateThread of ReadShell(Send) Error." ascii //weight: 1
        $x_1_2 = "CreateThread of WriteShell(Recv) Error." ascii //weight: 1
        $x_1_3 = "NPCommunication" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


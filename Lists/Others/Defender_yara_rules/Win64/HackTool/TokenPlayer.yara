rule HackTool_Win64_TokenPlayer_P_2147973214_0
{
    meta:
        author = "defender2yara"
        detection_name = "HackTool:Win64/TokenPlayer.P!MTB"
        threat_id = "2147973214"
        type = "HackTool"
        platform = "Win64: Windows 64-bit platform"
        family = "TokenPlayer"
        severity = "High"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "9"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "[-]Target isn't vulnerable!" ascii //weight: 1
        $x_1_2 = "[+]ImpersonateLoggedOnUser() succeed!" ascii //weight: 1
        $x_1_3 = "Specify the PID of the parent process you want to spoof." ascii //weight: 1
        $x_1_4 = "Spawn a new instance of an application with spoofed parent process." ascii //weight: 1
        $x_1_5 = "Will try to bypass UAC using the token-duplication method." ascii //weight: 1
        $x_1_6 = "Execute an instance of a specified program under the impersonated context." ascii //weight: 1
        $x_1_7 = "Spawns a new command prompt under the context of the stolen token." ascii //weight: 1
        $x_1_8 = "Proccess ID to steal the token from." ascii //weight: 1
        $x_1_9 = "Impersonates the specified pid and spawns a new child process under its context." ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


rule Backdoor_Win64_LilithRat_GA_2147809626_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win64/LilithRat.GA!MTB"
        threat_id = "2147809626"
        type = "Backdoor"
        platform = "Win64: Windows 64-bit platform"
        family = "LilithRat"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "9"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "keydump" ascii //weight: 1
        $x_1_2 = "keylog.txt" ascii //weight: 1
        $x_1_3 = "log.txt" ascii //weight: 1
        $x_1_4 = "remoteControl" ascii //weight: 1
        $x_1_5 = "command" ascii //weight: 1
        $x_1_6 = "powershell.exe" ascii //weight: 1
        $x_1_7 = "GetAsyncKeyState" ascii //weight: 1
        $x_1_8 = "[LMOUSE]" ascii //weight: 1
        $x_1_9 = "Restart requested: Restarting self" ascii //weight: 1
        $x_1_10 = "Termination requested: Killing self" ascii //weight: 1
        $x_1_11 = "Couldn't write to CMD: CMD not ope" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (9 of ($x*))
}


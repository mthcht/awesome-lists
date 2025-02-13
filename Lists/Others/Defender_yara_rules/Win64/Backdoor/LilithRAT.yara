rule Backdoor_Win64_LilithRAT_GB_2147820152_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win64/LilithRAT.GB!MTB"
        threat_id = "2147820152"
        type = "Backdoor"
        platform = "Win64: Windows 64-bit platform"
        family = "LilithRAT"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "16"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "\\Lilith-master\\x64\\Debug\\Lilith.pdb" ascii //weight: 10
        $x_5_2 = "127.0.0.1" ascii //weight: 5
        $x_1_3 = "keylog.txt" ascii //weight: 1
        $x_1_4 = "log.txt" ascii //weight: 1
        $x_1_5 = "getasynckeystate" ascii //weight: 1
        $x_1_6 = "Keylogger" ascii //weight: 1
        $x_1_7 = "killing self" ascii //weight: 1
        $x_1_8 = "powershell.exe" ascii //weight: 1
        $x_1_9 = "keydump" ascii //weight: 1
        $x_1_10 = "remoteControl" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_10_*) and 6 of ($x_1_*))) or
            ((1 of ($x_10_*) and 1 of ($x_5_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}


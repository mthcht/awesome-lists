rule Trojan_Win64_Blackout_A_2147848432_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Blackout.A!MTB"
        threat_id = "2147848432"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Blackout"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "Blackout.exe -p <process_id>" ascii //weight: 2
        $x_2_2 = "Terminating Windows Defender" ascii //weight: 2
        $x_2_3 = "\\\\.\\Blackout" wide //weight: 2
        $x_2_4 = "Blackout.sys" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


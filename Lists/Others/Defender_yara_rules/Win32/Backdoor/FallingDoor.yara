rule Backdoor_Win32_FallingDoor_A_2147641123_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/FallingDoor.gen!A"
        threat_id = "2147641123"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "FallingDoor"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "11"
        strings_accuracy = "High"
    strings:
        $x_3_1 = "UpFile----PreStart" wide //weight: 3
        $x_2_2 = "QQPassword" wide //weight: 2
        $x_3_3 = "ChatMsg---" wide //weight: 3
        $x_1_4 = "KillProces" wide //weight: 1
        $x_2_5 = "PrDownFile" wide //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


rule Trojan_Win64_HVNCStealer_RPH_2147834659_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/HVNCStealer.RPH!MTB"
        threat_id = "2147834659"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "HVNCStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "SKAVENCLIENT" wide //weight: 1
        $x_1_2 = "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run" wide //weight: 1
        $x_1_3 = "module.exe" wide //weight: 1
        $x_1_4 = "ProgramData\\log.txt" wide //weight: 1
        $x_1_5 = "[BACKSPACE]" wide //weight: 1
        $x_1_6 = "[CAPS LOCK]" wide //weight: 1
        $x_1_7 = "Sleep" ascii //weight: 1
        $x_1_8 = "passwords.txt" ascii //weight: 1
        $x_1_9 = "stealer send log" ascii //weight: 1
        $x_1_10 = "key.log" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


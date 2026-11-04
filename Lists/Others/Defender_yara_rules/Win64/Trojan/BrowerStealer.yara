rule Trojan_Win64_BrowerStealer_NB_2147981400_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/BrowerStealer.NB!MTB"
        threat_id = "2147981400"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "BrowerStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "15"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run" ascii //weight: 1
        $x_1_2 = "schtasks /create /tn" ascii //weight: 1
        $x_2_3 = "card_number_encrypted" ascii //weight: 2
        $x_1_4 = "Network\\Cookies" ascii //weight: 1
        $x_1_5 = "Login Data" ascii //weight: 1
        $x_1_6 = "NtWriteVirtualMemory" ascii //weight: 1
        $x_2_7 = "STEALER_RECON" ascii //weight: 2
        $x_2_8 = "keylogger started" ascii //weight: 2
        $x_2_9 = "persistence installed" ascii //weight: 2
        $x_1_10 = "selfdestruct" ascii //weight: 1
        $x_1_11 = "screenshot" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


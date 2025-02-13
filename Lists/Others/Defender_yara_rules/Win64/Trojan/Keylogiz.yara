rule Trojan_Win64_Keylogiz_A_2147917647_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Keylogiz.A!MTB"
        threat_id = "2147917647"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Keylogiz"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "GetSystemInfo" ascii //weight: 1
        $x_1_2 = ".GetAsyncKeyState" ascii //weight: 1
        $x_1_3 = ".GetKeyboardState" ascii //weight: 1
        $x_1_4 = "Keylogger-main/main.go" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


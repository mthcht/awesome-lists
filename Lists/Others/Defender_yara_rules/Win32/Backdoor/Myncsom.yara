rule Backdoor_Win32_Myncsom_2147936059_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Myncsom"
        threat_id = "2147936059"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Myncsom"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "ExecAppWaitWithUAC" ascii //weight: 1
        $x_1_2 = "You must load a DLL with same architecture as current process!" wide //weight: 1
        $x_1_3 = ".F601" wide //weight: 1
        $x_1_4 = ".hj6n" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

rule Backdoor_Win32_Myncsom_2147936059_1
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Myncsom"
        threat_id = "2147936059"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Myncsom"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "\\Plugin\\Passwords\\SynCrypto.pas" wide //weight: 1
        $x_1_2 = "powershell -Command \"Add-MpPreference -ExclusionPath" wide //weight: 1
        $x_1_3 = "{\"OffKeyLog\":\"%s\",\"MonitoringAPI\":\"%s\",\"ReplaceClipboard\":\"%s\"}" wide //weight: 1
        $x_1_4 = "Wombat Gaming Wallet" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}


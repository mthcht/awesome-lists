rule HackTool_Win32_Wirekeyview_2147694233_0
{
    meta:
        author = "defender2yara"
        detection_name = "HackTool:Win32/Wirekeyview!dha"
        threat_id = "2147694233"
        type = "HackTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Wirekeyview"
        severity = "High"
        info = "dha: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "100"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "WirelessKeyView" ascii //weight: 1
        $x_1_2 = "Policy\\PolSecretEncryptionKey" ascii //weight: 1
        $x_1_3 = "Microsoft\\WZCSVC\\Parameters\\Interfaces" ascii //weight: 1
        $x_1_4 = "AppData\\Roaming\\Microsoft\\Protect" ascii //weight: 1
        $x_1_5 = "\"%s\" /GetKeys %s" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


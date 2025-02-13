rule Worm_Win32_Nohad_ON_2147746193_0
{
    meta:
        author = "defender2yara"
        detection_name = "Worm:Win32/Nohad.ON!MTB"
        threat_id = "2147746193"
        type = "Worm"
        platform = "Win32: Windows 32-bit platform"
        family = "Nohad"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "\\nod42.exe" ascii //weight: 1
        $x_1_2 = "\\nottepad.exe" ascii //weight: 1
        $x_1_3 = "open=temp\\system.exe" ascii //weight: 1
        $x_1_4 = "\\Microsoft\\Windows\\Start Menu\\Programs\\Startup" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


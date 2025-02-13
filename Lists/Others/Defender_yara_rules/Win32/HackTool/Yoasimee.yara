rule HackTool_Win32_Yoasimee_A_2147742170_0
{
    meta:
        author = "defender2yara"
        detection_name = "HackTool:Win32/Yoasimee.A"
        threat_id = "2147742170"
        type = "HackTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Yoasimee"
        severity = "High"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Please enable UAC for this account." wide //weight: 1
        $x_1_2 = "Admin account with limited token required." wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


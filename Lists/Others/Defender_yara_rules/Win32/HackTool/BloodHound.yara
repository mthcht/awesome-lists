rule HackTool_Win32_BloodHound_A_2147741560_0
{
    meta:
        author = "defender2yara"
        detection_name = "HackTool:Win32/BloodHound.A"
        threat_id = "2147741560"
        type = "HackTool"
        platform = "Win32: Windows 32-bit platform"
        family = "BloodHound"
        severity = "High"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "BloodHound.bin" wide //weight: 1
        $x_1_2 = "samaccountname" ascii //weight: 1
        $x_1_3 = "_BloodHound.zip" wide //weight: 1
        $x_1_4 = "Sharphound2.JsonObjects" ascii //weight: 1
        $x_1_5 = "SharpHound.exe" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}


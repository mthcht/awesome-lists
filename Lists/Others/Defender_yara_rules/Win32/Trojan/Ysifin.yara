rule Trojan_Win32_Ysifin_A_2147901999_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Ysifin.A!MTB"
        threat_id = "2147901999"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Ysifin"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "Select Name from Win32_Process Where Name" wide //weight: 2
        $x_2_2 = "SCHTASKS /DELETE /TN" wide //weight: 2
        $x_2_3 = "SET someOtherProgram=SomeOtherProgram.exe" wide //weight: 2
        $x_2_4 = "TASKKILL /IM" wide //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


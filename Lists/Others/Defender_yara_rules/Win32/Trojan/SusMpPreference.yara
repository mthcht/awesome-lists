rule Trojan_Win32_SusMpPreference_A_2147958190_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/SusMpPreference.A"
        threat_id = "2147958190"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "SusMpPreference"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "powershell.exe -c" ascii //weight: 1
        $x_1_2 = "Add-MpPreference" ascii //weight: 1
        $x_1_3 = "-ExclusionPath" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_SusMpPreference_B_2147958191_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/SusMpPreference.B"
        threat_id = "2147958191"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "SusMpPreference"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "powershell.exe -c" ascii //weight: 1
        $x_1_2 = "Add-MpPreference" ascii //weight: 1
        $x_1_3 = "-ExclusionProcess" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


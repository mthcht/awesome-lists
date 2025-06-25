rule Trojan_Win32_CompEnum_ZZZ_2147944598_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/CompEnum.ZZZ!MTB"
        threat_id = "2147944598"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "CompEnum"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "owershell -coM" wide //weight: 1
        $x_1_2 = {74 00 65 00 6d 00 70 00 [0-255] 2e 00 74 00 6d 00 70 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_CompEnum_ZZC_2147944599_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/CompEnum.ZZC!MTB"
        threat_id = "2147944599"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "CompEnum"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Register-ScheduledTask" wide //weight: 1
        $x_1_2 = "[guid]::NewGuid().ToString().Substring(" wide //weight: 1
        $x_1_3 = "Action (New-ScheduledTaskAction -WorkingDirectory" wide //weight: 1
        $x_1_4 = "-Execute" wide //weight: 1
        $x_1_5 = "-Trigger (New-ScheduledTaskTrigger -Once -At (Get-Date) -RepetitionInterval (New-TimeSpan" wide //weight: 1
        $x_1_6 = "-Settings (New-ScheduledTaskSettingsSet" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


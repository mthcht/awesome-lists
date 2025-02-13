rule Backdoor_Win32_Soeda_A_2147695185_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Soeda.A!dha"
        threat_id = "2147695185"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Soeda"
        severity = "Critical"
        info = "dha: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "<!--?*$@" ascii //weight: 1
        $x_1_2 = "Range: bytes=%d-" ascii //weight: 1
        $x_1_3 = "result?sid=" ascii //weight: 1
        $x_1_4 = "win32.%d.%d.%d.%d.%d.%s" ascii //weight: 1
        $x_1_5 = "|%u|%u|%u|%u|%u" ascii //weight: 1
        $x_1_6 = "microsoftservices.proxydns.com" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_Win32_Soeda_B_2147695186_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Soeda.B!dha"
        threat_id = "2147695186"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Soeda"
        severity = "Critical"
        info = "dha: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Tiger324{" ascii //weight: 1
        $x_1_2 = "#runhfcore-" ascii //weight: 1
        $x_1_3 = "#runfile-" ascii //weight: 1
        $x_1_4 = "We probably tried to inject into an process" wide //weight: 1
        $x_1_5 = "Elevation:Administrator!new:{" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


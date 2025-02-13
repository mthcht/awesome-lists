rule Trojan_Win32_Fraudropper_A_2147796000_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Fraudropper.A!MTB"
        threat_id = "2147796000"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Fraudropper"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "9"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "ViottoBinder_Stub" ascii //weight: 1
        $x_1_2 = "|viottobinder||vttbndr|MZ" ascii //weight: 1
        $x_1_3 = "$77Redownloader.exe" wide //weight: 1
        $x_1_4 = "$77main1.exe" ascii //weight: 1
        $x_1_5 = "Application path" wide //weight: 1
        $x_1_6 = "Application data" wide //weight: 1
        $x_1_7 = "AppData" wide //weight: 1
        $x_1_8 = "WinDir" wide //weight: 1
        $x_1_9 = "2147483648" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


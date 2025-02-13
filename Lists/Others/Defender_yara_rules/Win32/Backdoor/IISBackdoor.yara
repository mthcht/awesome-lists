rule Backdoor_Win32_IISBackdoor_A_2147777389_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/IISBackdoor.A"
        threat_id = "2147777389"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "IISBackdoor"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_3_1 = "IIS_backdoor_dll.dll" ascii //weight: 3
        $x_3_2 = "IIS-Backdoor." ascii //weight: 3
        $x_1_3 = "C:\\Windows\\Temp\\creds.db" ascii //weight: 1
        $x_1_4 = "CHttpModule::OnPostBeginRequest" ascii //weight: 1
        $x_1_5 = "X-Password" ascii //weight: 1
        $x_1_6 = "No Creds Found" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((3 of ($x_1_*))) or
            ((1 of ($x_3_*))) or
            (all of ($x*))
        )
}


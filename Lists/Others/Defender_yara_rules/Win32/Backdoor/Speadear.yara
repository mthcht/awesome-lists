rule Backdoor_Win32_Speadear_A_2147727788_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Speadear.A"
        threat_id = "2147727788"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Speadear"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "%SystemRoot%\\System32\\svchost.exe -k" ascii //weight: 1
        $x_1_2 = "spdirs.dll" ascii //weight: 1
        $x_1_3 = "RegSetValueEx(Svchost\\netsvcs)" ascii //weight: 1
        $x_1_4 = {49 6e 73 74 61 6c 6c 41 00 49 6e 73 74 61 6c 6c 42 00 49 6e 73 74 61 6c 6c 43}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


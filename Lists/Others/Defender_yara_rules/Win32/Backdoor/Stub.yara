rule Backdoor_Win32_Stub_P_2147598836_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Stub.P"
        threat_id = "2147598836"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Stub"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "12"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "MSG $nick hey, check this out" ascii //weight: 1
        $x_1_2 = "\\Documents and Settings\\All Users\\Start Menu\\Programs\\Startup\\" ascii //weight: 1
        $x_1_3 = "\\WINDOWS\\Start Menu\\Programs\\Startup\\" ascii //weight: 1
        $x_1_4 = "\\WINNT\\Profiles\\All Users\\Start Menu\\Programs\\Startup\\" ascii //weight: 1
        $x_1_5 = "Windows\\CurrentVersion\\Uninstall\\eDonkey2000" ascii //weight: 1
        $x_1_6 = "\\software\\Morpheus" ascii //weight: 1
        $x_1_7 = "\\My Shared Folder" ascii //weight: 1
        $x_1_8 = "\\software\\Xolox" ascii //weight: 1
        $x_1_9 = "\\software\\Kazaa" ascii //weight: 1
        $x_1_10 = "\\software\\Shareaza" ascii //weight: 1
        $x_1_11 = "\\software\\LimeWire" ascii //weight: 1
        $x_1_12 = "Stubbos Bot" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


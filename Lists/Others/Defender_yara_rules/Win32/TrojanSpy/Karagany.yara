rule TrojanSpy_Win32_Karagany_A_2147804150_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:Win32/Karagany.A"
        threat_id = "2147804150"
        type = "TrojanSpy"
        platform = "Win32: Windows 32-bit platform"
        family = "Karagany"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "M:\\flash\\other\\C++\\LiteLoader 1.1\\Release\\keylog.pdb" ascii //weight: 2
        $x_1_2 = "KeylogHelperThread: Stop Keylog" ascii //weight: 1
        $x_1_3 = {5b 4c 43 54 52 4c 5d 00 5b 52 43 54 52 4c 5d 00 5b 49 4e 53 45 52 54 5d}  //weight: 1, accuracy: High
        $x_1_4 = "C:\\%APPDATA%\\Sql\\klog.dbc" ascii //weight: 1
        $x_1_5 = "Member Window" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((4 of ($x_1_*))) or
            ((1 of ($x_2_*) and 2 of ($x_1_*))) or
            (all of ($x*))
        )
}


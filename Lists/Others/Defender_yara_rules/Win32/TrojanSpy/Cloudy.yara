rule TrojanSpy_Win32_Cloudy_A_2147723388_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:Win32/Cloudy.A!bit"
        threat_id = "2147723388"
        type = "TrojanSpy"
        platform = "Win32: Windows 32-bit platform"
        family = "Cloudy"
        severity = "Critical"
        info = "bit: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "cloudyservs.com" ascii //weight: 1
        $x_1_2 = "User-Agent: Cloudy" ascii //weight: 1
        $x_1_3 = "Global\\{JQZXC-52964-GTHJ-QKIU-56POUYT}" ascii //weight: 1
        $x_1_4 = "Software\\Microsoft\\Windows\\CurrentVersion\\Run" ascii //weight: 1
        $x_1_5 = "\\Release\\Cloudy.pdb" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (4 of ($x*))
}


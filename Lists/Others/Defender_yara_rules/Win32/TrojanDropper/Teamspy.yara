rule TrojanDropper_Win32_Teamspy_A_2147709659_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:Win32/Teamspy.A!bit"
        threat_id = "2147709659"
        type = "TrojanDropper"
        platform = "Win32: Windows 32-bit platform"
        family = "Teamspy"
        severity = "Critical"
        info = "bit: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "wextract_cleanup%d" ascii //weight: 1
        $x_1_2 = "Software\\Microsoft\\Windows\\CurrentVersion\\RunOnce" ascii //weight: 1
        $x_1_3 = "EXE /verysilent /Password=1234522222" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


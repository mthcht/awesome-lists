rule TrojanSpy_Win32_Nocturnal_A_2147727858_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:Win32/Nocturnal.A!bit"
        threat_id = "2147727858"
        type = "TrojanSpy"
        platform = "Win32: Windows 32-bit platform"
        family = "Nocturnal"
        severity = "Critical"
        info = "bit: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "ProgramData\\Arkei" ascii //weight: 1
        $x_1_2 = "ProgramData\\Nocturnal" ascii //weight: 1
        $x_1_3 = "\\files\\filezilla_sitemanager.xml" ascii //weight: 1
        $x_1_4 = "Bitcoin\\wallet.dat" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}


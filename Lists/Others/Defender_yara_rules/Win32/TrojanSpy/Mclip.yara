rule TrojanSpy_Win32_Mclip_A_2147727480_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:Win32/Mclip.A!bit"
        threat_id = "2147727480"
        type = "TrojanSpy"
        platform = "Win32: Windows 32-bit platform"
        family = "Mclip"
        severity = "Critical"
        info = "bit: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "TWJ2aG9zdC5leGU=" ascii //weight: 1
        $x_1_2 = "c2NodGFza3MuZXhl" ascii //weight: 1
        $x_1_3 = "L2NyZWF0ZSAvdG4gXE1pY3Jvc29mdFxXaW5kb3dzXE1pY2xp" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


rule TrojanDropper_Win32_Insnot_B_2147804039_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:Win32/Insnot.gen!B"
        threat_id = "2147804039"
        type = "TrojanDropper"
        platform = "Win32: Windows 32-bit platform"
        family = "Insnot"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Pricate - Adult codec" ascii //weight: 1
        $x_1_2 = "@$&%04\\codec.exe" ascii //weight: 1
        $x_1_3 = "@$&%04\\loadernew.exe" ascii //weight: 1
        $x_1_4 = "Russian (" ascii //weight: 1
        $x_1_5 = "Codec?" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


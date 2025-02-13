rule Worm_Win32_Kasatall_A_2147633095_0
{
    meta:
        author = "defender2yara"
        detection_name = "Worm:Win32/Kasatall.A"
        threat_id = "2147633095"
        type = "Worm"
        platform = "Win32: Windows 32-bit platform"
        family = "Kasatall"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "AASSKK" ascii //weight: 2
        $x_1_2 = "fooool.exe" ascii //weight: 1
        $x_1_3 = "[VVflagRun]" ascii //weight: 1
        $x_1_4 = "D:\\Data.bat" ascii //weight: 1
        $x_1_5 = "[AutoRun]" ascii //weight: 1
        $x_1_6 = "Flash Game 2007\\Setup Game.exe" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((5 of ($x_1_*))) or
            ((1 of ($x_2_*) and 3 of ($x_1_*))) or
            (all of ($x*))
        )
}


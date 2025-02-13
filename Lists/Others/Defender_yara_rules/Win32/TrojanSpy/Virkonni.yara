rule TrojanSpy_Win32_Virkonni_A_2147762266_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:Win32/Virkonni.A!MSR"
        threat_id = "2147762266"
        type = "TrojanSpy"
        platform = "Win32: Windows 32-bit platform"
        family = "Virkonni"
        severity = "Critical"
        info = "MSR: Microsoft Security Response"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "http://member-daumchk.netai.net/weget/download.php?file=787C1648_dropcom" ascii //weight: 2
        $x_2_2 = "http://%s/weget/download.php?file=%s_dropcom" ascii //weight: 2
        $x_1_3 = "INTERNAL\\REMOTE.EXE" wide //weight: 1
        $x_1_4 = "This computer's IP Address is" ascii //weight: 1
        $x_1_5 = "yself.dll" ascii //weight: 1
        $x_1_6 = "Packages\\microsoft\\repaired" wide //weight: 1
        $x_1_7 = "0626\\virus-load\\_Result64\\virus-dll.pdb" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 5 of ($x_1_*))) or
            ((2 of ($x_2_*) and 3 of ($x_1_*))) or
            (all of ($x*))
        )
}


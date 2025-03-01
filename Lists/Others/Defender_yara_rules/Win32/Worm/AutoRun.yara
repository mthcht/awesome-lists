rule Worm_Win32_AutoRun_XXY_2147724667_0
{
    meta:
        author = "defender2yara"
        detection_name = "Worm:Win32/AutoRun.XXY!bit"
        threat_id = "2147724667"
        type = "Worm"
        platform = "Win32: Windows 32-bit platform"
        family = "AutoRun"
        severity = "Critical"
        info = "bit: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "13"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "Injecting ->" ascii //weight: 2
        $x_2_2 = "InjUpdate" ascii //weight: 2
        $x_2_3 = {48 6f 6f 6b 4f 6e 00 00 48 6f 6f 6b 4f 66 66}  //weight: 2, accuracy: High
        $x_2_4 = "autorun.inf" ascii //weight: 2
        $x_2_5 = "shellexecute=" ascii //weight: 2
        $x_2_6 = "Software\\Microsoft\\Windows\\CurrentVersion\\Run" ascii //weight: 2
        $x_1_7 = "USB Hooks -> Active" ascii //weight: 1
        $x_1_8 = "Keyboard Hook -> Active" ascii //weight: 1
        $x_1_9 = "Auto Mail Sender -> Active" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((5 of ($x_2_*) and 3 of ($x_1_*))) or
            ((6 of ($x_2_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}


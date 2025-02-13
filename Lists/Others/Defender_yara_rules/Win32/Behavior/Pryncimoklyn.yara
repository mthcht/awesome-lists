rule Behavior_Win32_Pryncimoklyn_A_2147722006_0
{
    meta:
        author = "defender2yara"
        detection_name = "Behavior:Win32/Pryncimoklyn.A!rsm"
        threat_id = "2147722006"
        type = "Behavior"
        platform = "Win32: Windows 32-bit platform"
        family = "Pryncimoklyn"
        severity = "Critical"
        info = "rsm: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "400"
        strings_accuracy = "High"
    strings:
        $x_100_1 = "_HELP_INSTRUCTION.TXT" wide //weight: 100
        $x_100_2 = "%s%08X%08X%08X%08X.MOLE02" wide //weight: 100
        $x_100_3 = "vssadmin.exe Delete Shadows /All /Quiet" ascii //weight: 100
        $x_100_4 = "!!! Your DECRYPT-ID: %s !!!" wide //weight: 100
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


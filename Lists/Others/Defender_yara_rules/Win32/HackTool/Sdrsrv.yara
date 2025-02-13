rule HackTool_Win32_Sdrsrv_A_2147723367_0
{
    meta:
        author = "defender2yara"
        detection_name = "HackTool:Win32/Sdrsrv.A!dha"
        threat_id = "2147723367"
        type = "HackTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Sdrsrv"
        severity = "High"
        info = "dha: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "70"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "C:\\Windows\\temp\\l.tmp" wide //weight: 10
        $x_10_2 = "args[10] is %S and command is %S" ascii //weight: 10
        $x_10_3 = "CHECKING %d of %d" ascii //weight: 10
        $x_10_4 = "[COUNT] %d" ascii //weight: 10
        $x_10_5 = "[FINISHED]" ascii //weight: 10
        $x_10_6 = "vminst.tmp" wide //weight: 10
        $x_10_7 = "[OK]" ascii //weight: 10
        $x_10_8 = "LOGON USER FAILD " ascii //weight: 10
        $x_10_9 = "IMPESONATE FAILD " ascii //weight: 10
        $x_10_10 = "ERROR in %S/%d" ascii //weight: 10
        $x_100_11 = "P:\\Projects\\C++\\Trojan\\Target\\Sdrsrv\\Win32\\Release\\Sdrsrv.pdb" ascii //weight: 100
    condition:
        (filesize < 20MB) and
        (
            ((7 of ($x_10_*))) or
            ((1 of ($x_100_*))) or
            (all of ($x*))
        )
}


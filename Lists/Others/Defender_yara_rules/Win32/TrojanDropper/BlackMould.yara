rule TrojanDropper_Win32_BlackMould_A_2147746176_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:Win32/BlackMould.A!dha"
        threat_id = "2147746176"
        type = "TrojanDropper"
        platform = "Win32: Windows 32-bit platform"
        family = "BlackMould"
        severity = "Critical"
        info = "dha: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "%windir%\\system32\\inetsrv\\srvhttp.dll" ascii //weight: 2
        $x_2_2 = "SrvHttpModule" ascii //weight: 2
        $x_1_3 = "HttpSrvModule" ascii //weight: 1
        $x_2_4 = "To configure ApplicationHost.config file OK..." ascii //weight: 2
        $x_1_5 = "unstall" ascii //weight: 1
        $x_1_6 = "[ERROR]:CreateFile to %ws(%s) error..." ascii //weight: 1
        $x_1_7 = "CreateFile %ws(%s) OK..." ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 3 of ($x_1_*))) or
            ((2 of ($x_2_*) and 1 of ($x_1_*))) or
            ((3 of ($x_2_*))) or
            (all of ($x*))
        )
}


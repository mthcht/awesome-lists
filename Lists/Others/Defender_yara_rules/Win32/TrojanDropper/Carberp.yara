rule TrojanDropper_Win32_Carberp_A_2147658412_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:Win32/Carberp.A"
        threat_id = "2147658412"
        type = "TrojanDropper"
        platform = "Win32: Windows 32-bit platform"
        family = "Carberp"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "daemonupd.exe /svc" ascii //weight: 1
        $x_1_2 = "\\Microsoft\\Windows\\winupdate.exe" ascii //weight: 1
        $x_1_3 = "nvUpdService" ascii //weight: 1
        $x_1_4 = "winupdate.lnk" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


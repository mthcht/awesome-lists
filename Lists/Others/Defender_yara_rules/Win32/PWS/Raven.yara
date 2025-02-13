rule PWS_Win32_Raven_A_2147650775_0
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:Win32/Raven.gen!A"
        threat_id = "2147650775"
        type = "PWS"
        platform = "Win32: Windows 32-bit platform"
        family = "Raven"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "\\wcx_ftp.ini" ascii //weight: 1
        $x_1_2 = "Software\\Microsoft\\Windows\\CurrentVersion\\Run" ascii //weight: 1
        $x_3_3 = "_mutex_file_fake" ascii //weight: 3
        $x_2_4 = "_event_upd_afil" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


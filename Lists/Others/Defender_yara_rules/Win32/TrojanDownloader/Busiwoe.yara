rule TrojanDownloader_Win32_Busiwoe_A_2147625056_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Busiwoe.A"
        threat_id = "2147625056"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Busiwoe"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "woecd.businessconsults.net" ascii //weight: 1
        $x_1_2 = "Logon user err!" ascii //weight: 1
        $x_1_3 = "process-cmd-stopped" ascii //weight: 1
        $x_1_4 = "APVSVC" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


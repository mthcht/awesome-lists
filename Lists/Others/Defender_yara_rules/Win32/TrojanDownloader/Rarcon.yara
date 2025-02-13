rule TrojanDownloader_Win32_Rarcon_A_2147654795_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Rarcon.A"
        threat_id = "2147654795"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Rarcon"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {77 69 6e 72 61 72 5f 63 6f 6e 66 69 67 2e 74 6d 70 00 00 00 20 3e 20 6e 75 6c}  //weight: 1, accuracy: High
        $x_1_2 = "n9n.net/" ascii //weight: 1
        $x_1_3 = "://kp.9" ascii //weight: 1
        $x_1_4 = "uan.ico" ascii //weight: 1
        $x_1_5 = {73 74 61 72 74 2f 6d 69 6e 20 00 00 6f 6b 2e 62 61 74}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (4 of ($x*))
}

rule TrojanDownloader_Win32_Rarcon_B_2147656464_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Rarcon.B"
        threat_id = "2147656464"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Rarcon"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "23"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "SOFTWARE\\WinRAR" ascii //weight: 10
        $x_10_2 = "cdf1912.tmp" ascii //weight: 10
        $x_10_3 = "winrar_config.tmp" ascii //weight: 10
        $x_2_4 = "D:\\VolumeDH" ascii //weight: 2
        $x_1_5 = "\\tao" ascii //weight: 1
        $x_1_6 = "tuan.ico" ascii //weight: 1
        $x_1_7 = "net.exe" ascii //weight: 1
        $x_1_8 = "\\inj." ascii //weight: 1
        $x_1_9 = ".wav" ascii //weight: 1
        $x_1_10 = "start/min" ascii //weight: 1
        $x_1_11 = "udate" ascii //weight: 1
        $x_1_12 = "uname" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_10_*) and 3 of ($x_1_*))) or
            ((2 of ($x_10_*) and 1 of ($x_2_*) and 1 of ($x_1_*))) or
            ((3 of ($x_10_*))) or
            (all of ($x*))
        )
}


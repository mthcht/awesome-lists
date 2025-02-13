rule TrojanDownloader_Win32_Phinit_A_2147622433_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Phinit.A"
        threat_id = "2147622433"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Phinit"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "304"
        strings_accuracy = "Low"
    strings:
        $x_100_1 = {25 73 5c 25 73 2e 69 6e 69 [0-4] 25 73}  //weight: 100, accuracy: Low
        $x_100_2 = "DllCanUnloadNow" ascii //weight: 100
        $x_100_3 = "%Y-%m-%d" ascii //weight: 100
        $x_3_4 = "http://%s/up/update.htm" ascii //weight: 3
        $x_3_5 = "http://%s/page/ap.asp" ascii //weight: 3
        $x_1_6 = "Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\Shell Folders" ascii //weight: 1
        $x_1_7 = "SYSTEM\\CurrentControlSet\\Services\\Eventlog" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((3 of ($x_100_*) and 1 of ($x_3_*) and 1 of ($x_1_*))) or
            ((3 of ($x_100_*) and 2 of ($x_3_*))) or
            (all of ($x*))
        )
}

rule TrojanDownloader_Win32_Phinit_B_2147626778_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Phinit.B"
        threat_id = "2147626778"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Phinit"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "%s\\kbietmp2.ini" ascii //weight: 1
        $x_1_2 = "USNSVC" ascii //weight: 1
        $x_1_3 = "/up/update.htm" ascii //weight: 1
        $x_1_4 = "!*&*none-value*&!*" ascii //weight: 1
        $x_1_5 = "InternetOpenUrlA" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


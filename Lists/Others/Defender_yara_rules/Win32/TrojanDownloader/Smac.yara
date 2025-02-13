rule TrojanDownloader_Win32_Smac_B_2147716508_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Smac.B!dha"
        threat_id = "2147716508"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Smac"
        severity = "Critical"
        info = "dha: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "x-DownOnly(" wide //weight: 1
        $x_1_2 = "x-Exec(" wide //weight: 1
        $x_1_3 = "Execute success!" wide //weight: 1
        $x_1_4 = "smac=" wide //weight: 1
        $x_1_5 = "&sres=" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_Win32_Smac_C_2147716548_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Smac.C!dha"
        threat_id = "2147716548"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Smac"
        severity = "Critical"
        info = "dha: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "x-DownOnly(" wide //weight: 1
        $x_1_2 = "x-Exec(" wide //weight: 1
        $x_1_3 = "[C-r-e-a-t-e b-a-t f-i-l-e failed!]" wide //weight: 1
        $x_1_4 = "[E-x-e-c f-a-i-l-e-d!]" wide //weight: 1
        $x_1_5 = "[D-o-w-n s-u-c-c-e-s-s:" wide //weight: 1
        $x_1_6 = "%supdate%d.bat" wide //weight: 1
        $x_1_7 = "[Upload success: %d Bytes" wide //weight: 1
        $x_1_8 = "[Execute failed!]" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (5 of ($x*))
}


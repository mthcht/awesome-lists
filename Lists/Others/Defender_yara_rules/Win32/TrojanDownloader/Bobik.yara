rule TrojanDownloader_Win32_Bobik_RP_2147905908_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Bobik.RP!MTB"
        threat_id = "2147905908"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Bobik"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "66"
        strings_accuracy = "High"
    strings:
        $x_20_1 = "timebosspro-setup.exe" ascii //weight: 20
        $x_20_2 = "Nicekit.TimeBoss.FormMain.resources" ascii //weight: 20
        $x_20_3 = "Time Boss Pro" wide //weight: 20
        $x_5_4 = "ht$/nic6oad/new/" wide //weight: 5
        $x_5_5 = "ht$/niceki#wnload/new/" wide //weight: 5
        $x_5_6 = "ht$/niceki1wnload/new/" wide //weight: 5
        $x_5_7 = "ht$/nic#oad/new/" wide //weight: 5
        $x_1_8 = "ekit.ru/downl" wide //weight: 1
        $x_1_9 = "t.ru/do" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((3 of ($x_20_*) and 1 of ($x_5_*) and 1 of ($x_1_*))) or
            ((3 of ($x_20_*) and 2 of ($x_5_*))) or
            (all of ($x*))
        )
}


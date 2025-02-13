rule TrojanDownloader_Win32_Tyqui_A_2147628491_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Tyqui.A"
        threat_id = "2147628491"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Tyqui"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "tikkysoft web downloader\\stub" wide //weight: 1
        $x_1_2 = "</FILE>" wide //weight: 1
        $x_1_3 = "If Exist" wide //weight: 1
        $x_1_4 = "systemdrive" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_Win32_Tyqui_B_2147630300_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Tyqui.B"
        threat_id = "2147630300"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Tyqui"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "</FILE>" wide //weight: 1
        $x_1_2 = "</URL>" wide //weight: 1
        $x_1_3 = "If Exist" wide //weight: 1
        $x_1_4 = "systemdrive" wide //weight: 1
        $x_3_5 = {bd 78 ff ff ff 00 0f 84 4d 05 00 00 8d 55 8c 8d 4d bc}  //weight: 3, accuracy: High
        $x_3_6 = {c7 45 94 20 1b 40 00 c7 45 8c 08 00 00 00}  //weight: 3, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_3_*) and 3 of ($x_1_*))) or
            ((2 of ($x_3_*))) or
            (all of ($x*))
        )
}


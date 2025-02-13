rule TrojanDownloader_Win32_Votwup_A_2147627020_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Votwup.gen!A"
        threat_id = "2147627020"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Votwup"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "Low"
    strings:
        $x_3_1 = {80 7d fb 01 75 ?? 81 ff b8 0b 00 00 76 ?? 6a 01 6a 00}  //weight: 3, accuracy: Low
        $x_3_2 = {6a 02 6a 00 6a 00 e8 ?? ?? ff ff e8 ?? ?? ff ff 3d b7 00 00 00 75 05}  //weight: 3, accuracy: Low
        $x_1_3 = "ms_ie" ascii //weight: 1
        $x_1_4 = ":*:Enabled:" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_3_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule TrojanDownloader_Win32_Votwup_D_2147656148_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Votwup.D"
        threat_id = "2147656148"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Votwup"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "Zp_stealer" ascii //weight: 1
        $x_1_2 = {64 64 31 00}  //weight: 1, accuracy: High
        $x_1_3 = {3f 75 69 64 3d 00}  //weight: 1, accuracy: High
        $x_1_4 = "System\\Drk\\" ascii //weight: 1
        $x_1_5 = "TBotThread" ascii //weight: 1
        $x_1_6 = "---------------------------282861610524488" ascii //weight: 1
        $x_1_7 = {80 7d fb 01 75 ?? 81 fb b8 0b 00 00 76 ?? 6a 01 6a 00 6a 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


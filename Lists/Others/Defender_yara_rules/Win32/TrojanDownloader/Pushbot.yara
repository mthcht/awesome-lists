rule TrojanDownloader_Win32_Pushbot_A_2147633867_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Pushbot.A"
        threat_id = "2147633867"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Pushbot"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {99 6a 1a 59 f7 f9 83 c2 61 89 55 f8 8d 45 f8 50 ff 75 fc [0-32] 50 68 04 01 00 00 ff 15 ?? ?? ?? 00 6a 03 e8 ?? ff ff ff}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_Win32_Pushbot_D_2147637966_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Pushbot.D"
        threat_id = "2147637966"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Pushbot"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "11"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {43 00 3a 00 5c 00 41 00 6c 00 6c 00 20 00 46 00 69 00 6c 00 65 00 73 00 5c 00 [0-32] 2e 00 76 00 62 00 70 00}  //weight: 10, accuracy: Low
        $x_1_2 = "thpt/:w/wwm.syapecc.mob/orsw/erbwoesa.ps" ascii //weight: 1
        $x_1_3 = "thpt/:9/.371.4498./7d~nerilu/" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_10_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}


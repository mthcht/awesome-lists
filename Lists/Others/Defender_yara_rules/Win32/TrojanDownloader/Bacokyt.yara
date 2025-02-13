rule TrojanDownloader_Win32_Bacokyt_A_2147685497_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Bacokyt.A"
        threat_id = "2147685497"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Bacokyt"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "14"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "spinltzsoftwareltda.info/skyhdtv-drivegenios04/ApiSocket64Bytes.bck" ascii //weight: 10
        $x_6_2 = "maisumavezconta.info/escrita/" ascii //weight: 6
        $x_4_3 = {5c 41 76 61 73 74 68 69 73 74 6f 72 79 00 00 00 ff ff ff ff 0a 00 00 00 63 6f 6e 74 61 64 6f 72}  //weight: 4, accuracy: High
        $x_2_4 = "ashQuick.exe" ascii //weight: 2
        $x_2_5 = "&DetectAntiVirus=" ascii //weight: 2
        $x_2_6 = "&GetWinVersionAsStringWinArch=" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_6_*) and 1 of ($x_4_*) and 2 of ($x_2_*))) or
            ((1 of ($x_10_*) and 2 of ($x_2_*))) or
            ((1 of ($x_10_*) and 1 of ($x_4_*))) or
            ((1 of ($x_10_*) and 1 of ($x_6_*))) or
            (all of ($x*))
        )
}


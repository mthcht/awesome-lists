rule TrojanDownloader_Win32_Droma_A_2147719484_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Droma.A!bit"
        threat_id = "2147719484"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Droma"
        severity = "Critical"
        info = "bit: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Flag_Running_" wide //weight: 1
        $x_1_2 = "1qazXSW@3edcVFR$5tgbNHY" ascii //weight: 1
        $x_1_3 = "10293847-5-6-Download&%d/" ascii //weight: 1
        $x_1_4 = "\\command.com /c" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


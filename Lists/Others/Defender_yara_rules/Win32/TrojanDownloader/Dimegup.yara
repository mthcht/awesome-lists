rule TrojanDownloader_Win32_Dimegup_A_2147682847_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Dimegup.A"
        threat_id = "2147682847"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Dimegup"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "\\m_editerror.tmp" ascii //weight: 1
        $x_1_2 = "http://networksecurityx.hopto.org" ascii //weight: 1
        $x_1_3 = "xxxx_xxxx_xxxx" ascii //weight: 1
        $x_1_4 = {8b c7 33 d2 f7 75 14 8b 45 0c 0f b6 04 02 03 06 03 c3 8b d9 99 f7 fb 8a 06 47 88 45 ff 8b da}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}


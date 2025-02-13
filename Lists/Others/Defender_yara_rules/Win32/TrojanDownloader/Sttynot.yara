rule TrojanDownloader_Win32_Sttynot_A_2147625477_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Sttynot.gen!A"
        threat_id = "2147625477"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Sttynot"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8a 54 1a ff 80 f2 ?? 88 54 18 ff 43 4e 75 e6}  //weight: 1, accuracy: Low
        $x_1_2 = {ba 01 08 00 00 e8 ?? ?? ?? ?? 6a 00 68 01 08 00 00 8d 85 ?? ?? ff ff 50 53 e8}  //weight: 1, accuracy: Low
        $x_1_3 = "?status=activated&type=run&node=xyz&task=incomplete&notify=true&brand=" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


rule TrojanDownloader_Win32_URLDistract_A_2147629864_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/URLDistract.A"
        threat_id = "2147629864"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "URLDistract"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "87105110100111119115327884" wide //weight: 1
        $x_1_2 = "Dicionario.vbp" wide //weight: 1
        $x_1_3 = {0f bf 55 cc 0f bf 45 d4 8b 4d d8 33 d0 51 52 ff 15 ?? ?? ?? ?? 8b d0 8d 4d c4 ff d6 50 ff 15 ?? ?? ?? ?? 8b d0 8d 4d d8 ff d6 8d 4d c4 ff d3 b8 02 00 00 00 66 03 c7 70 73 8b f8 e9 f2 fe ff ff}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


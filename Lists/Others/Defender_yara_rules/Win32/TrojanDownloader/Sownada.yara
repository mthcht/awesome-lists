rule TrojanDownloader_Win32_Sownada_A_2147631287_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Sownada.A"
        threat_id = "2147631287"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Sownada"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "</durum>" wide //weight: 1
        $x_1_2 = "</site>" wide //weight: 1
        $x_1_3 = "sonunda oldu" wide //weight: 1
        $x_1_4 = "\\msnservices" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


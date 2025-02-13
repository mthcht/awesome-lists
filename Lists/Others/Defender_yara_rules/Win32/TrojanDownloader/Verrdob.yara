rule TrojanDownloader_Win32_Verrdob_A_2147650947_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Verrdob.A"
        threat_id = "2147650947"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Verrdob"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "pD0EPJNhTvUE" wide //weight: 2
        $x_1_2 = "pJyhTJsQpJ0gTDsgpJy" wide //weight: 1
        $x_1_3 = "pD0g8JsQ" wide //weight: 1
        $x_1_4 = "pDU6TvXVpvH6TvNOpi0gpvN7piTEpDHd" wide //weight: 1
        $x_1_5 = "pDThPDsdpD0gpD8ypDAg8v8VpD0" wide //weight: 1
        $x_1_6 = "pJTE0dN7pvTE0vAQpyNg0vAQpd0E8vAQpd0EpD" wide //weight: 1
        $x_1_7 = "py0EPDNdpdAE8vHdpiNEpvHgTvUhpdN7pisEpJ" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((5 of ($x_1_*))) or
            ((1 of ($x_2_*) and 3 of ($x_1_*))) or
            (all of ($x*))
        )
}


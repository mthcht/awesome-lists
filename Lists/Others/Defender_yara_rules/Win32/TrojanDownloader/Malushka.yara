rule TrojanDownloader_Win32_Malushka_T_2147618620_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Malushka.T"
        threat_id = "2147618620"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Malushka"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "42"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "document.botgoway.submit()" ascii //weight: 10
        $x_10_2 = "<referer>*</referer>" ascii //weight: 10
        $x_10_3 = "HTTPULTIMALINK:" ascii //weight: 10
        $x_10_4 = "Connection: Keep-Alive" ascii //weight: 10
        $x_1_5 = "%3D0&stc&url=http://www.goog" ascii //weight: 1
        $x_1_6 = "/click_second_new3.php" ascii //weight: 1
        $x_1_7 = "escape(window.location.href)" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((4 of ($x_10_*) and 2 of ($x_1_*))) or
            (all of ($x*))
        )
}


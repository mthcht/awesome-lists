rule Trojan_Win32_ExtenBro_A_2147695695_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/ExtenBro.A"
        threat_id = "2147695695"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "ExtenBro"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "34"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {3c 6e 61 6d 65 3e 51 75 69 63 6b 20 53 65 61 72 63 68 65 72 [0-4] 3c 2f 6e 61 6d 65 3e}  //weight: 10, accuracy: Low
        $x_10_2 = {3c 65 6d 3a 64 65 73 63 72 69 70 74 69 6f 6e 3e 51 75 69 63 6b 20 53 65 61 72 63 68 65 72 [0-4] 3c 2f 65 6d 3a 64 65 73 63 72 69 70 74 69 6f 6e 3e}  //weight: 10, accuracy: Low
        $x_10_3 = "127.0.0.1 clients2.google.com" ascii //weight: 10
        $x_10_4 = "\\signal.dat" ascii //weight: 10
        $x_1_5 = "\\Yandex\\YandexBrowser\\User Data\\Default\\" ascii //weight: 1
        $x_1_6 = "\\Amigo\\User Data\\Default\\Extension Data" ascii //weight: 1
        $x_1_7 = "\\Opera Software\\Opera Stable\\Preferences" ascii //weight: 1
        $x_1_8 = "AvastSvc.exe" ascii //weight: 1
        $x_1_9 = "avgrsx.exe" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((3 of ($x_10_*) and 4 of ($x_1_*))) or
            ((4 of ($x_10_*))) or
            (all of ($x*))
        )
}


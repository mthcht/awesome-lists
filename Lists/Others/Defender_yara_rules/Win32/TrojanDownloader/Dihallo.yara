rule TrojanDownloader_Win32_Dihallo_A_2147803903_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Dihallo.A"
        threat_id = "2147803903"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Dihallo"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "60"
        strings_accuracy = "High"
    strings:
        $x_20_1 = "E23319E4-31EA-4221-8DDD-990E27CB755F" ascii //weight: 20
        $x_20_2 = "hallo" ascii //weight: 20
        $x_5_3 = "InternetConnectA" ascii //weight: 5
        $x_5_4 = "RasEnumDevicesA" ascii //weight: 5
        $x_5_5 = "&lid=0x%x&slid=0x%x&vm=%d&d=%#04d%#02d%#02d&t=%#02d%#02d%#02d&b=%d&dd1=%s" ascii //weight: 5
        $x_5_6 = "jexe1" ascii //weight: 5
        $x_1_7 = "modem" ascii //weight: 1
        $x_1_8 = "isdn" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_20_*) and 4 of ($x_5_*))) or
            (all of ($x*))
        )
}

rule TrojanDownloader_Win32_Dihallo_A_2147803903_1
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Dihallo.A"
        threat_id = "2147803903"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Dihallo"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "40"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "InternetConnectA" ascii //weight: 10
        $x_10_2 = "RasEnumDevicesA" ascii //weight: 10
        $x_7_3 = "E23319E4-31EA-4221-8DDD-990E27CB755F" ascii //weight: 7
        $x_5_4 = "&lid=0x%x&slid=0x%x&vm=%d&d=%#04d%#02d%#02d&t=%#02d%#02d%#02d&b=%d&dd1=%s" ascii //weight: 5
        $x_5_5 = "jexe1" ascii //weight: 5
        $x_1_6 = "modem" ascii //weight: 1
        $x_1_7 = "isdn" ascii //weight: 1
        $x_3_8 = "C:\\TEMP\\d.bat" ascii //weight: 3
        $x_5_9 = "&lscal=%#04d%#02d%#02d%#02d%#02d%#02d" ascii //weight: 5
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_10_*) and 3 of ($x_5_*) and 1 of ($x_3_*) and 2 of ($x_1_*))) or
            ((2 of ($x_10_*) and 1 of ($x_7_*) and 2 of ($x_5_*) and 1 of ($x_3_*))) or
            ((2 of ($x_10_*) and 1 of ($x_7_*) and 3 of ($x_5_*))) or
            (all of ($x*))
        )
}


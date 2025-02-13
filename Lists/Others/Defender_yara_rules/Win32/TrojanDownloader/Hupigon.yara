rule TrojanDownloader_Win32_Hupigon_A_2147627042_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Hupigon.A"
        threat_id = "2147627042"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Hupigon"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = ".dll,download" wide //weight: 1
        $x_1_2 = "\\vbame.dll" wide //weight: 1
        $x_1_3 = "http://www.sxbattery.com" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_Win32_Hupigon_B_2147627044_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Hupigon.B"
        threat_id = "2147627044"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Hupigon"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {60 00 10 ff 15 08 50 00 10 8b f8 68 ?? 60 00 10 57 ff 15 04 50 00 10 8b f0 6a 00 6a 00 68 ?? 60 00 10 68 ?? 60 00 10 6a 00 ff d6 83 c4 14 85 c0 74 e7 57 ff 15 00 50 00 10 5f 5e c3 8b 44 24 08 83 f8 01 0f 85 88 00 00 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_Win32_Hupigon_E_2147654142_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Hupigon.E"
        threat_id = "2147654142"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Hupigon"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "%s\\urlmoonk.dll" ascii //weight: 1
        $x_1_2 = "%sLoadlogging" ascii //weight: 1
        $x_1_3 = {6a 0c 50 68 04 00 00 98 ff b6 a8 00 00 00}  //weight: 1, accuracy: High
        $x_1_4 = {8b 8e 68 a4 00 00 83 c4 1c 89 84 8e 28 08 00 00 ff 86 68 a4 00 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


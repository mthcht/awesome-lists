rule TrojanDownloader_Win32_ClickFixMshta_A_2147977141_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/ClickFixMshta.A"
        threat_id = "2147977141"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "ClickFixMshta"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "21"
        strings_accuracy = "High"
    strings:
        $x_20_1 = "cmd /c" wide //weight: 20
        $x_20_2 = "cmd.exe /c" wide //weight: 20
        $x_1_3 = "m^s^h^t^a" wide //weight: 1
        $x_1_4 = "m^s^h^ta" wide //weight: 1
        $x_1_5 = "m^s^ht^a" wide //weight: 1
        $x_1_6 = "m^sh^t^a" wide //weight: 1
        $x_1_7 = "ms^h^t^a" wide //weight: 1
        $x_1_8 = "m^s^hta" wide //weight: 1
        $x_1_9 = "m^sh^ta" wide //weight: 1
        $x_1_10 = "m^sht^a" wide //weight: 1
        $x_1_11 = "ms^h^ta" wide //weight: 1
        $x_1_12 = "ms^ht^a" wide //weight: 1
        $x_1_13 = "msh^t^a" wide //weight: 1
        $x_1_14 = "m^shta" wide //weight: 1
        $x_1_15 = "ms^hta" wide //weight: 1
        $x_1_16 = "msht^a" wide //weight: 1
        $x_1_17 = "msh^ta" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_20_*) and 1 of ($x_1_*))) or
            ((2 of ($x_20_*))) or
            (all of ($x*))
        )
}


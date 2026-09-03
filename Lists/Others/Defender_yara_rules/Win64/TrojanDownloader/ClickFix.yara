rule TrojanDownloader_Win64_ClickFix_MSHTA_2147977296_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win64/ClickFix.MSHTA"
        threat_id = "2147977296"
        type = "TrojanDownloader"
        platform = "Win64: Windows 64-bit platform"
        family = "ClickFix"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "m^s^h^t^a" wide //weight: 1
        $x_1_2 = "m^s^h^ta" wide //weight: 1
        $x_1_3 = "m^s^ht^a" wide //weight: 1
        $x_1_4 = "m^sh^t^a" wide //weight: 1
        $x_1_5 = "ms^h^t^a" wide //weight: 1
        $x_1_6 = "m^s^hta" wide //weight: 1
        $x_1_7 = "m^sh^ta" wide //weight: 1
        $x_1_8 = "m^sht^a" wide //weight: 1
        $x_1_9 = "ms^h^ta" wide //weight: 1
        $x_1_10 = "ms^ht^a" wide //weight: 1
        $x_1_11 = "msh^t^a" wide //weight: 1
        $x_1_12 = "m^shta" wide //weight: 1
        $x_1_13 = "ms^hta" wide //weight: 1
        $x_1_14 = "msht^a" wide //weight: 1
        $x_1_15 = "msh^ta" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule TrojanDownloader_Win64_ClickFix_WebDAV_2147977449_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win64/ClickFix.WebDAV"
        threat_id = "2147977449"
        type = "TrojanDownloader"
        platform = "Win64: Windows 64-bit platform"
        family = "ClickFix"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "cmd.exe" wide //weight: 1
        $x_1_2 = "start" wide //weight: 1
        $x_1_3 = "/v:on" wide //weight: 1
        $x_1_4 = "pushd&set" wide //weight: 1
        $x_1_5 = "rundll32&call" wide //weight: 1
        $x_1_6 = "@SSL" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


rule TrojanDownloader_Win32_Astaroth_KH_2147919968_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Astaroth.KH"
        threat_id = "2147919968"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Astaroth"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "mshta " wide //weight: 1
        $x_1_2 = "javascript:var " wide //weight: 1
        $x_1_3 = {74 00 72 00 79 00 [0-4] 67 00 65 00 74 00 6f 00 62 00 6a 00 65 00 63 00 74 00 [0-255] 63 00 61 00 74 00 63 00 68 00 28 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_Win32_Astaroth_KG_2147919969_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Astaroth.KG"
        threat_id = "2147919969"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Astaroth"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "echo " wide //weight: 1
        $x_1_2 = "\\programdata\\" wide //weight: 1
        $x_1_3 = {62 00 69 00 74 00 73 00 61 00 64 00 6d 00 69 00 6e 00 [0-4] 2f 00 72 00 65 00 73 00 65 00 74 00 [0-16] 65 00 78 00 69 00 74 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_Win32_Astaroth_YY_2147919970_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Astaroth.YY"
        threat_id = "2147919970"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Astaroth"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "112"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "cmd.exe" wide //weight: 1
        $x_1_2 = "\\ProgramData\\" wide //weight: 1
        $x_10_3 = "curl -A" wide //weight: 10
        $x_100_4 = {68 00 74 00 74 00 70 00 73 00 3a 00 2f 00 2f 00 [0-255] 2f 00 3f 00 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 20 00 2d 00 6f 00 20 00}  //weight: 100, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


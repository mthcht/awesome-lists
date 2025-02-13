rule TrojanDownloader_Win32_Zurgop_C_2147731791_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Zurgop.C!bit"
        threat_id = "2147731791"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Zurgop"
        severity = "Critical"
        info = "bit: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "Software\\localNETService" ascii //weight: 1
        $x_1_2 = {8a 4c 35 d4 32 0c 02 32 ca 46 83 fe 10 88 0c 02 75 02 33 f6 42 3b d3 72 e7}  //weight: 1, accuracy: High
        $x_1_3 = {69 72 73 2e c7 81 ?? ?? ?? ?? 69 72 77 2e c7 81 ?? ?? ?? ?? 31 61 66 69}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_Win32_Zurgop_YT_2147906770_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Zurgop.YT!MTB"
        threat_id = "2147906770"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Zurgop"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "qrstuvwxyzeioubdabcdefghijklmnop4hifie56a7b&#d3wH" ascii //weight: 1
        $x_1_2 = "Local\\{C15730E2-145C-4c5e-B005-3BC753F42475}-once-flag" ascii //weight: 1
        $x_1_3 = "\\resource-a.dat" ascii //weight: 1
        $x_1_4 = "http://" ascii //weight: 1
        $x_1_5 = "/search/?q=" ascii //weight: 1
        $x_1_6 = "InternetOpenUrlA" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


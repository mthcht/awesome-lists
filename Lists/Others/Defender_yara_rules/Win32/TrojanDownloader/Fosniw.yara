rule TrojanDownloader_Win32_Fosniw_B_2147642016_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Fosniw.B"
        threat_id = "2147642016"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Fosniw"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {75 0d 68 f4 01 00 00 ff d5 46 83 fe 78 7c c9}  //weight: 1, accuracy: High
        $x_1_2 = {c6 44 24 0c 37 89 54 24 ?? 66 89 44 24 ?? e8 ?? ?? ?? ?? 33 f6 80 7c 24 ?? 00 0f 86 ?? ?? ?? ?? 8d 64 24 00 6a 40 8d 54 24 0c 6a 00 52 e8 [0-9] 83 c4 0c 8d 4c 24 ?? 51 c6 44 24 0c 32}  //weight: 1, accuracy: Low
        $x_1_3 = {8b 54 24 10 80 f1 ?? 88 0c ?? ?? 83 ?? 04 [0-4] 3b ?? 72}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (2 of ($x*))
}

rule TrojanDownloader_Win32_Fosniw_C_2147642209_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Fosniw.C"
        threat_id = "2147642209"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Fosniw"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "11"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "app.iekeyword.com" ascii //weight: 1
        $x_1_2 = "app.keywordkr.com" ascii //weight: 1
        $x_1_3 = "appx.koreasys1.com" ascii //weight: 1
        $x_5_4 = {2f 72 65 63 65 69 76 65 2f 72 5f 61 75 74 6f 69 64 63 6e 74 2e 61 73 70 3f 6d 65 72 5f 73 65 71 3d 25 73 26 72 65 61 6c 69 64 3d 25 73 26 63 6e 74 5f 74 79 70 65 3d [0-2] 26 6d 61 63 3d 25 73}  //weight: 5, accuracy: Low
        $x_5_5 = "?prj=%s&pid=%s&mac=%s&logdata=MacTryCnt:%d&code=%s&ver=%s" ascii //weight: 5
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_5_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule TrojanDownloader_Win32_Fosniw_D_2147643160_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Fosniw.D"
        threat_id = "2147643160"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Fosniw"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {c6 44 24 0c 37 [0-80] c6 44 24 0c 32 [0-96] c6 44 24 ?? 33}  //weight: 1, accuracy: Low
        $x_1_2 = "IEKeyword" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_Win32_Fosniw_G_2147655565_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Fosniw.G"
        threat_id = "2147655565"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Fosniw"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "p.keywordkr.com/" ascii //weight: 1
        $x_1_2 = "/receive/r_autoidcnt.asp?mer_seq=%s&realid=%s&cnt_type=e8&mac=%s" ascii //weight: 1
        $x_1_3 = "?prj=%s&pid=%s&qy=%s&mac=%s&w=%d&h=%d" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


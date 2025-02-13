rule TrojanDownloader_Win32_Minuplo_A_2147693395_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Minuplo.A"
        threat_id = "2147693395"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Minuplo"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {6c 73 61 73 2e 65 78 65 00}  //weight: 1, accuracy: High
        $x_1_2 = "miniupload.net/me/s1.php" ascii //weight: 1
        $x_1_3 = "ni386755_3.fastdownload.nitrado.net/ir_updatex.exe" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_Win32_Minuplo_B_2147693396_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Minuplo.B"
        threat_id = "2147693396"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Minuplo"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {63 73 72 73 73 72 2e 65 78 65 00}  //weight: 1, accuracy: High
        $x_1_2 = "miniupload.net/ir/s1.php" ascii //weight: 1
        $x_1_3 = "miniupload.net/ir/url" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


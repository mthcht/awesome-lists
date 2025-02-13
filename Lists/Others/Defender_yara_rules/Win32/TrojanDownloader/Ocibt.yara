rule TrojanDownloader_Win32_Ocibt_A_2147642864_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Ocibt.A"
        threat_id = "2147642864"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Ocibt"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "/POPUP" ascii //weight: 1
        $x_1_2 = "\\system32\\win7zip.dll" ascii //weight: 1
        $x_1_3 = "http://go.myzy.info/down.php?i=bdll&" ascii //weight: 1
        $x_1_4 = "http://go.myzy.info/down.php?i=bexe&" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_Win32_Ocibt_A_2147642864_1
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Ocibt.A"
        threat_id = "2147642864"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Ocibt"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "/POPUP" ascii //weight: 1
        $x_1_2 = "http://go.iuyt.info/down.php?i=tbico&" ascii //weight: 1
        $x_1_3 = "http:/go.iuyt.info/down.php?i=avbs&" ascii //weight: 1
        $x_1_4 = "\\winrar\\ico\\taobao.tbico" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_Win32_Ocibt_A_2147642864_2
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Ocibt.A"
        threat_id = "2147642864"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Ocibt"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "/POPUP" ascii //weight: 1
        $x_1_2 = {68 74 74 70 3a 2f 2f 6d 6d 35 38 2e 66 72 65 65 6e 76 2e 69 6e 66 6f 3a 37 37 37 2f [0-32] 2e 70 68 70 3f 6d 61 63 3d}  //weight: 1, accuracy: Low
        $x_1_3 = "http://go.iuyt.info/down.php?i=a&" ascii //weight: 1
        $x_1_4 = "http://go.iuyt.info/down.php?i=take&" ascii //weight: 1
        $x_1_5 = {5c 61 61 31 5f fd 83 80 fd 84 80 fd 85 80 2e 65 78 65}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_Win32_Ocibt_B_2147648132_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Ocibt.B"
        threat_id = "2147648132"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Ocibt"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_3_1 = "\\winrar\\ico\\taobao.tbico" ascii //weight: 3
        $x_1_2 = "http://nsis.sf.net/NSIS_Error" ascii //weight: 1
        $x_2_3 = "?i=tbico&" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


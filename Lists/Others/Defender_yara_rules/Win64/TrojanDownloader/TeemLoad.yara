rule TrojanDownloader_Win64_TeemLoad_A_2147972923_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win64/TeemLoad.A!dha"
        threat_id = "2147972923"
        type = "TrojanDownloader"
        platform = "Win64: Windows 64-bit platform"
        family = "TeemLoad"
        severity = "Critical"
        info = "dha: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Teems Update" wide //weight: 1
        $x_1_2 = "Global\\GHPA" wide //weight: 1
        $x_1_3 = "/JBIKSij8bhvdBHBVDH878svbn/" wide //weight: 1
        $x_1_4 = "tag=%s&id=%s" wide //weight: 1
        $x_1_5 = "Mozilla/5.0 (Windows NT 10.0; Win64; x64)" wide //weight: 1
        $x_1_6 = "%s---%s" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


rule VirTool_Win64_NuRnsm_A_2147901516_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win64/NuRnsm.A"
        threat_id = "2147901516"
        type = "VirTool"
        platform = "Win64: Windows 64-bit platform"
        family = "NuRnsm"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "Decrypt instead of encrypting" ascii //weight: 2
        $x_2_2 = "Read/write AES key from/to [file] or download/upload from/to [url]" ascii //weight: 2
        $x_2_3 = "Folder(s) to recursively encrypt or decrypt" ascii //weight: 2
        $x_2_4 = "file|url" ascii //weight: 2
        $x_2_5 = "key-file" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


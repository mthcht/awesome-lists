rule Ransom_Win64_NEFH_MKV_2147973423_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win64/NEFH.MKV!MTB"
        threat_id = "2147973423"
        type = "Ransom"
        platform = "Win64: Windows 64-bit platform"
        family = "NEFH"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {45 31 c0 4c 89 c0 31 d2 4c 89 c1 48 f7 f6 4c 89 c0 48 c1 e9 ?? 49 83 c0 01 44 31 d1 41 83 c2 ?? 4c 8d 0c 13 31 d2 48 f7 f7 41 32 09 32 4c 15 00 c0 c1 03 41 88 09 4d 39 d8 75}  //weight: 5, accuracy: Low
        $x_2_2 = "'IM A VICTIM OF THE NEFH RANSOMWARE'" ascii //weight: 2
        $x_1_3 = "OOPS! your files are encrypted!" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


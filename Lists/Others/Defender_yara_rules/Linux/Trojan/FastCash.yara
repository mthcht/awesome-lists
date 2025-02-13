rule Trojan_Linux_FastCash_A_2147925436_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Linux/FastCash.A!MTB"
        threat_id = "2147925436"
        type = "Trojan"
        platform = "Linux: Linux platform"
        family = "FastCash"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {48 8b 55 d0 48 8b 45 c0 48 01 d0 48 89 c6 48 8b 55 c8 48 8b 45 c0 48 01 d0 48 89 c1 48 8b 45 e0 48 89 c2 48 89 cf e8 e4 ?? ?? ?? 8b 45 bc 85 c0 7e ?? 48 8b 45 c8 48 2b 45 d0 48 89 45 e8 48 b8 ff ff ff 7f ff ff ff ff 48 39 45 e8 7e ?? b8 00 00 00 80 48 39 45 e8}  //weight: 1, accuracy: Low
        $x_1_2 = {55 48 89 e5 48 83 c4 80 48 89 7d a8 48 89 75 a0 48 89 55 98 48 89 4d ?? 44 89 45 8c 64 48 8b 04 25 28 00 00 00 48 89 45 f8 31 c0 48 c7 45 c0 00 00 00 00 48 8b 45 a8 48 89 45 c8 48 8b 45 a0 48 89 45 d0 48 8b 05 55 5e 00 00 48 8b 00 48 85 c0 74 ?? 48 8b 05 46 5e 00 00 48 8b 00}  //weight: 1, accuracy: Low
        $x_1_3 = "/mnt/hgfs/MyFc/MyFc/subhook/subhook_x86.c" ascii //weight: 1
        $x_1_4 = "/tmp/trans.dat" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


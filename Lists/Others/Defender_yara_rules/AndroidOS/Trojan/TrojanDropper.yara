rule Trojan_AndroidOS_TrojanDropper_AB_2147818278_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:AndroidOS/TrojanDropper.AB"
        threat_id = "2147818278"
        type = "Trojan"
        platform = "AndroidOS: Android operating system"
        family = "TrojanDropper"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {dd 4a dd 4b d0 f8 84 60 7a 44 7b 44 58 46 b0 47 02 46 da 48 29 46 78 44 d0 f8 00 80 58 46 c0 47 81 46 db f8 00 00 d6 49 82 69 79 44 58 46 90 47 05 46 db f8 00 00 d3 4a 29 46 d3 4b d0 f8 84 60 7a 44 7b 44 58 46 b0 47 06 46 db f8 00 00 cf 4a 29 46 d0 f8 84 40 7a 44 ce 4b 58 46 7b 44 a0 47 06 90}  //weight: 2, accuracy: High
        $x_2_2 = {6c 69 62 63 2e 73 6f 00 6c 69 62 ?? ?? 2e 73 6f 00 5f 5f 63 78 61 5f 66 69 6e 61 6c 69 7a 65 00 [0-49] 4a 61 76 61 5f 6a 5f 6b 63 5f 67 61 7a 00 4a 61 76 61 5f 6a 5f 6f 69 5f 62 62 66 00 4a 61 76 61 5f 6a 5f 6f 69 5f 64 76 67 00 4a 61 76 61 5f 6a 5f 6f 69 5f 65 7a 00}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


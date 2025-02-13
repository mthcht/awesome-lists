rule Ransom_Win64_PANDORA_REL_2147815562_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win64/PANDORA.REL!MTB"
        threat_id = "2147815562"
        type = "Ransom"
        platform = "Win64: Windows 64-bit platform"
        family = "PANDORA"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {48 ff cf 48 85 db 75 2b 4d 8b c6 48 8b d5 49 8b cd e8 8a f1 ff ff ba 01 00 00 00 48 8d 45 0f 48 2b d5 80 00 01 75 0c 48 ff c8 48 8d 0c 02 48 85 c9 7f ef 42 0f b6 0c 33 41 0f b6 04 37 32 c8 88 0e 48 ff c6 48 ff c3 83 e3 0f 48 85 ff}  //weight: 1, accuracy: High
        $n_100_2 = "usage: rsa_verify_pss <key_file> <filename>" ascii //weight: -100
    condition:
        (filesize < 20MB) and
        (not (any of ($n*))) and
        (all of ($x*))
}


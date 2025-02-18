rule Trojan_Script_PowerFlare_A_2147933707_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Script/PowerFlare.A!dha"
        threat_id = "2147933707"
        type = "Trojan"
        platform = "Script: "
        family = "PowerFlare"
        severity = "Critical"
        info = "dha: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {70 00 6f 00 77 00 65 00 72 00 73 00 68 00 65 00 6c 00 6c 00 2e 00 65 00 78 00 65 00 20 00 2d 00 77 00 20 00 68 00 69 00 64 00 64 00 65 00 6e 00 20 00 2d 00 6e 00 6f 00 65 00 78 00 69 00 74 00 20 00 24 00 [0-64] 28 00 47 00 65 00 74 00 2d 00 49 00 74 00 65 00 6d 00 50 00 72 00 6f 00 70 00 65 00 72 00 74 00 79 00 20 00 2d 00 50 00 61 00 74 00 68 00 20 00 48 00 4b 00 43 00 55 00 3a 00 5c 00 53 00 79 00 73 00 74 00 65 00 6d 00 20 00 2d 00 4e 00 61 00 6d 00 65 00 [0-64] 3d 00 5b 00 73 00 63 00 72 00 69 00 70 00 74 00 62 00 6c 00 6f 00 63 00 6b 00 5d 00 3a 00 3a 00 43 00 72 00 65 00 61 00 74 00 65 00 28 00 [0-21] 3b 00 20 00 26 00 20 00 24 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


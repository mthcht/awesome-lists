rule Trojan_AndroidOS_DropperGen_A_2147787316_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:AndroidOS/DropperGen.A"
        threat_id = "2147787316"
        type = "Trojan"
        platform = "AndroidOS: Android operating system"
        family = "DropperGen"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "11"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = "nfyqu.jar" ascii //weight: 10
        $x_1_2 = {5e 49 02 22 79 44 ?? ?? ?? ed 03 94 07 1c 00 28}  //weight: 1, accuracy: Low
        $x_1_3 = {79 23 03 70 83 70 78 23 c3 70 73 23 03 71 6d 23 43 71 70 23 83 71 67 23 c3 71 76 23 03 72 6b 23 83 72 6a 23 68 22 c3 72 66 23 42 70 03 73 72 22 83 73 62 23 c3 73 80 21 42 72 42 73 04 aa ?? ?? ?? fd 11 20 ?? ?? ?? ec 2d 4c 00 21 11 22 02 90 01 03 ec a8 1c 02 99 04 aa ?? ?? ?? f8}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_10_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Trojan_AndroidOS_DropperGen_B_2147787317_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:AndroidOS/DropperGen.B"
        threat_id = "2147787317"
        type = "Trojan"
        platform = "AndroidOS: Android operating system"
        family = "DropperGen"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Lcom/vod/hlum/gbuy" ascii //weight: 1
        $x_1_2 = "attachBaseContext" ascii //weight: 1
        $x_1_3 = "loadLibrary" ascii //weight: 1
        $x_1_4 = "nfyqu" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


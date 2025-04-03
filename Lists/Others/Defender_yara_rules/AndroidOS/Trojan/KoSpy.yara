rule Trojan_AndroidOS_KoSpy_A_2147937782_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:AndroidOS/KoSpy.A!MTB"
        threat_id = "2147937782"
        type = "Trojan"
        platform = "AndroidOS: Android operating system"
        family = "KoSpy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {6f 30 78 0f 06 08 55 60 1b 06 38 00 1c 00 70 10 cc 17 06 00 0a 00 39 00 16 00 6e 10 14 0c 06 00 0a 00 15 04 00 ff b5 40 15 04 00 01 33 40 04 00 01 30 28 02}  //weight: 1, accuracy: High
        $x_1_2 = {3d 0a 18 00 54 db 24 06 52 bc f8 01 52 bb f9 01 b0 bc b1 ca 71 10 af 0b 0e 00 0a 0e 71 20 b1 70 ea 00 0a 0e 71 20 b0 0b 9e 00 0a 0e 01 3a 28 02}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_AndroidOS_KoSpy_B_2147937783_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:AndroidOS/KoSpy.B!MTB"
        threat_id = "2147937783"
        type = "Trojan"
        platform = "AndroidOS: Android operating system"
        family = "KoSpy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {36 76 37 00 20 46 1f 01 38 06 33 00 71 00 9e 0d 00 00 0c 06 6e 10 9f 0d 06 00 0a 06 38 06 13 00 32 26 06 00 12 34 32 46 0e 00 28 22 1f 04 1f 01}  //weight: 1, accuracy: High
        $x_1_2 = {54 02 31 05 54 22 3c 05 54 04 30 05 54 05 a5 05 6e 40 03 30 42 51 0c 02 5b 02 a9 05 39 02 10 00 71 00 de 2f 00 00 0c 01 62 02 aa 05 1a 04 7f 17 23 33 1c 0d 6e 40 dc 2f 21 34 28 1d}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


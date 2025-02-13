rule Trojan_AndroidOS_ViceLeaker_B_2147798313_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:AndroidOS/ViceLeaker.B!MTB"
        threat_id = "2147798313"
        type = "Trojan"
        platform = "AndroidOS: Android operating system"
        family = "ViceLeaker"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {71 00 40 6d 00 00 0c 00 6e 10 3d 6d 00 00 0c 08 16 00 40 1f 71 20 eb 47 10 00 54 e0 6c 38 54 00 2d 38 1a 01 25 65 6e 20 fd 6c 10 00 0c 00 1a 01 88 34 71 20 e1 48 10 00 0c 00 1a 01 0a 06 6e 20 90 47 10 00 0c 05 54 e0 6c 38 22 01 a1 0b 1a 02 da 40 70 20 b9 47 21 00 12 02 46 02 05 02 6e 20 c1 47 21 00 0c 01 6e 10 ce 47 01 00 0c 01 6e 20 98 6c 10 00 54 e0 6c 38 22 01 a1 0b 1a 02 d2 70 70 20 b9 47 21 00 6e 20 c1 47 81 00 0c 01 6e 10 ce 47 01 00 0c 01 6e 20 98 6c 10 00 12 00 46 00 05 00 1a 01 d6 05 6e 20 7a 47 10 00 0a 00 38 00 38 00 54 e0 6c 38 54 00 2e 38 12 11 46 01 05 01 12 22 46 02 05 02 6e 30 dd 6c 10 02 54 e0 6c 38 54 00 2d 38 1a 01 37 47 6e 30 fa 6c 80 01}  //weight: 1, accuracy: High
        $x_1_2 = "/reqcalllog.php" ascii //weight: 1
        $x_1_3 = "30cmd90cmi03" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


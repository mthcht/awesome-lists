rule Trojan_MacOS_Gogetter_A_2147794884_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MacOS/Gogetter.A"
        threat_id = "2147794884"
        type = "Trojan"
        platform = "MacOS: "
        family = "Gogetter"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_MACHOHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "/bin/bash" ascii //weight: 1
        $x_1_2 = {68 74 74 70 3a 2f 2f 61 70 69 2e [0-15] 2e 63 6f 6d 2f 67 61 3f 61 3d 25 73 26 62 3d 25 73}  //weight: 1, accuracy: Low
        $x_1_3 = "IOPlatformExpertDevice" ascii //weight: 1
        $x_1_4 = "/tmp0x%x10803125" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


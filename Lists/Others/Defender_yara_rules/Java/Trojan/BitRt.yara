rule Trojan_Java_BitRt_A_2147784012_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Java/BitRt.A!MTB"
        threat_id = "2147784012"
        type = "Trojan"
        platform = "Java: Java binaries (classes)"
        family = "BitRt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_JAVAHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "payload.exe" ascii //weight: 1
        $x_1_2 = {62 69 74 73 61 64 6d 69 6e 2e 65 78 65 20 2f 74 72 61 6e 73 66 65 72 [0-16] 75 72 6c [0-32] 73 74 72 [0-5] 66 69 6c 65 6e 61 6d 65}  //weight: 1, accuracy: Low
        $x_2_3 = "://grntexpresscourier.com/File/" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


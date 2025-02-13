rule Trojan_Linux_Orbit_A_2147826080_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Linux/Orbit.A!MTB"
        threat_id = "2147826080"
        type = "Trojan"
        platform = "Linux: Linux platform"
        family = "Orbit"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "11"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {2f 6c 69 62 2f [0-21] 2f 73 73 68 70 61 73 73 2e 74 78 74}  //weight: 5, accuracy: Low
        $x_5_2 = {6d 76 20 2f 6c 69 62 2f [0-21] 2f 2e 62 61 63 6b 75 70 5f 6c 64 2e 73 6f}  //weight: 5, accuracy: Low
        $x_5_3 = "/tmp/.orbit" ascii //weight: 5
        $x_5_4 = "/dev/shm/.lck" ascii //weight: 5
        $x_1_5 = "sniff_ssh_session" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_5_*) and 1 of ($x_1_*))) or
            ((3 of ($x_5_*))) or
            (all of ($x*))
        )
}


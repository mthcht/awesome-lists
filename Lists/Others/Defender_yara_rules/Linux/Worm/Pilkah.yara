rule Worm_Linux_Pilkah_B_2147818563_0
{
    meta:
        author = "defender2yara"
        detection_name = "Worm:Linux/Pilkah.B!MTB"
        threat_id = "2147818563"
        type = "Worm"
        platform = "Linux: Linux platform"
        family = "Pilkah"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "ngsynflood" ascii //weight: 1
        $x_1_2 = "ackflood" ascii //weight: 1
        $x_1_3 = "ngackflood" ascii //weight: 1
        $x_1_4 = "/var/run/.lightpid" ascii //weight: 1
        $x_1_5 = "Lightaidra" ascii //weight: 1
        $x_1_6 = "get_spoofed" ascii //weight: 1
        $x_1_7 = "/var/run/.lightscan" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (6 of ($x*))
}


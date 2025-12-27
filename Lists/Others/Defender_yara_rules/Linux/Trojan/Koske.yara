rule Trojan_Linux_Koske_A_2147947774_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Linux/Koske.A!MTB"
        threat_id = "2147947774"
        type = "Trojan"
        platform = "Linux: Linux platform"
        family = "Koske"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "koske" ascii //weight: 2
        $x_2_2 = "readdir" ascii //weight: 2
        $x_1_3 = "hideproc" ascii //weight: 1
        $x_1_4 = "/dev/shm/.hiddenpid" ascii //weight: 1
        $x_1_5 = "/proc/self/fd/%d" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


rule DDoS_Linux_Gafgyt_YA_2147741748_0
{
    meta:
        author = "defender2yara"
        detection_name = "DDoS:Linux/Gafgyt.YA!MTB"
        threat_id = "2147741748"
        type = "DDoS"
        platform = "Linux: Linux platform"
        family = "Gafgyt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {3c 4e 65 77 53 74 61 74 75 73 55 52 4c 3e 24 28 2f 62 69 6e 2f 62 75 73 79 62 6f 78 20 77 67 65 74 20 2d 67 20 [0-3] 2e [0-3] 2e [0-3] 2e}  //weight: 1, accuracy: Low
        $x_1_2 = "POST /ctrlt/DeviceUpgrade_1" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


rule DDoS_Linux_Xarcen_A_2147830630_0
{
    meta:
        author = "defender2yara"
        detection_name = "DDoS:Linux/Xarcen.A!MTB"
        threat_id = "2147830630"
        type = "DDoS"
        platform = "Linux: Linux platform"
        family = "Xarcen"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {89 44 24 04 8d 85 e9 df ff ff 89 04 24 e8 27 f5 ff ff 8d 85 e9 df ff ff 89 74 24 0c c7 44 24 08 ?? ?? 0b 08 c7 44 24 04 00 10 00 00 89 04 24 e8 ?? ?? ?? 00 8d 85 e9 cf ff ff 89 04 24 e8 ?? ?? ?? 00 89 44 24 08 8d 85 e9 cf ff ff 89 44 24 04 8d 85 e9 df ff ff 89 04 24 e8 db f4 ff ff 8b 45 08}  //weight: 1, accuracy: Low
        $x_1_2 = "/etc/cron.hourly/%s.sh" ascii //weight: 1
        $x_1_3 = "denyip=" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


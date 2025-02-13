rule Backdoor_Linux_AnchorBot_B_2147767033_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Linux/AnchorBot.B!MTB"
        threat_id = "2147767033"
        type = "Backdoor"
        platform = "Linux: Linux platform"
        family = "AnchorBot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "/tmp/anchor.log" ascii //weight: 2
        $x_2_2 = "icanhazip.com" ascii //weight: 2
        $x_1_3 = "ftp://%s:%s@%s" ascii //weight: 1
        $x_1_4 = "smb2_write_async" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


rule HackTool_Linux_WildFire_A_2147935638_0
{
    meta:
        author = "defender2yara"
        detection_name = "HackTool:Linux/WildFire.A!MTB"
        threat_id = "2147935638"
        type = "HackTool"
        platform = "Linux: Linux platform"
        family = "WildFire"
        severity = "High"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "/bin/cp /tmp/panwtest /usr/bin/ps" ascii //weight: 1
        $x_1_2 = "Sample Executed Successfully." ascii //weight: 1
        $x_1_3 = {41 57 41 89 ff 41 56 49 89 f6 41 55 49 89 d5 41 54 4c 8d 25 48 08 20 00 55 48 8d 2d 48 08 20 00 53 4c 29 e5 31 db 48 c1 fd 03 48 83 ec 08 e8 35 fe ff ff 48 85 ed 74 1e 0f 1f 84 ?? ?? ?? ?? ?? 4c 89 ea 4c 89 f6 44 89 ff 41 ff 14 dc 48 83 c3 01 48 39 eb 75 ea 48 83 c4 08 5b 5d 41 5c 41 5d 41 5e 41 5f c3}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


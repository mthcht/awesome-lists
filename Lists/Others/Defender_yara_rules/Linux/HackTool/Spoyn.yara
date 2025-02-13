rule HackTool_Linux_Spoyn_A_2147825982_0
{
    meta:
        author = "defender2yara"
        detection_name = "HackTool:Linux/Spoyn.A!xp"
        threat_id = "2147825982"
        type = "HackTool"
        platform = "Linux: Linux platform"
        family = "Spoyn"
        severity = "High"
        info = "xp: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Spoofed SYN Attack" ascii //weight: 1
        $x_1_2 = "[x] Error sending packet" ascii //weight: 1
        $x_1_3 = "Usage: %s <Saldirilacak IP> <PORT> <SURE>" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (2 of ($x*))
}


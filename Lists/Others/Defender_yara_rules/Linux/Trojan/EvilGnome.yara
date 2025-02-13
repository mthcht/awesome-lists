rule Trojan_Linux_EvilGnome_B_2147773046_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Linux/EvilGnome.B!MTB"
        threat_id = "2147773046"
        type = "Trojan"
        platform = "Linux: Linux platform"
        family = "EvilGnome"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "sdg62_AS.sa$die3" ascii //weight: 1
        $x_1_2 = "rtp.dat" ascii //weight: 1
        $x_1_3 = "gnome-shell-ext" ascii //weight: 1
        $x_1_4 = "ShooterKey" ascii //weight: 1
        $x_1_5 = {53 68 6f 6f 74 65 72 49 6d 61 67 65 [0-2] 74 61 6b 65 53 63 72 65 65 6e 73 68 6f 74}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


rule Trojan_Linux_SaltWater_A_2147849232_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Linux/SaltWater.A!MTB"
        threat_id = "2147849232"
        type = "Trojan"
        platform = "Linux: Linux platform"
        family = "SaltWater"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {71 75 69 74 0d 0a 00 00 00 33 8c 25 3d 9c 17 70 08 f9 0c 1a 41 71 55 36 1a 5c 4b 8d 29 7e 0d 78}  //weight: 1, accuracy: High
        $x_1_2 = "UploadChannel" ascii //weight: 1
        $x_1_3 = "libbindshell.so" ascii //weight: 1
        $x_1_4 = "Connected2Vps" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Linux_SaltWater_B_2147849665_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Linux/SaltWater.B!MTB"
        threat_id = "2147849665"
        type = "Trojan"
        platform = "Linux: Linux platform"
        family = "SaltWater"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "mod_udp" ascii //weight: 1
        $x_1_2 = "libbindshell.so" ascii //weight: 1
        $x_1_3 = "UploadChannel" ascii //weight: 1
        $x_1_4 = "gethostbyname" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


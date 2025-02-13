rule Trojan_MacOS_OceanLotus_B_2147745470_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MacOS/OceanLotus.B!MTB"
        threat_id = "2147745470"
        type = "Trojan"
        platform = "MacOS: "
        family = "OceanLotus"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACHOHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {48 63 d2 41 8a 04 17 32 03 88 01 ff c2 44 39 f2 0f 4d d6 48 ff c3 48 ff c1 41 ff cd 75 e2}  //weight: 2, accuracy: High
        $x_2_2 = {88 84 15 d0 fe ff ff 40 88 c7 40 00 ff 40 30 c7 88 c3 c0 fb ?? 80 e3 ?? 0f b6 c0 88 94 05 d0 fd ff ff 40 30 fb 48 ff c2 81 fa 00 ?? ?? ?? 88 d8 75 ce}  //weight: 2, accuracy: Low
        $x_1_3 = "/tmp/crunzip.temp.XXXXXX" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 1 of ($x_1_*))) or
            ((2 of ($x_2_*))) or
            (all of ($x*))
        )
}

rule Trojan_MacOS_OceanLotus_A_2147787206_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MacOS/OceanLotus.A"
        threat_id = "2147787206"
        type = "Trojan"
        platform = "MacOS: "
        family = "OceanLotus"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_MACHOHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "com.apple.marcoagent.voiceinstallerd" ascii //weight: 2
        $x_1_2 = "/Library/User Photos" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


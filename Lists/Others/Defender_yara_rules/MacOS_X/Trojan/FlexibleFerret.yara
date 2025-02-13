rule Trojan_MacOS_X_FlexibleFerret_A_2147932986_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MacOS_X/FlexibleFerret.A!dha"
        threat_id = "2147932986"
        type = "Trojan"
        platform = "MacOS_X: "
        family = "FlexibleFerret"
        severity = "Critical"
        info = "dha: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_MACHOHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Password cannot be empty. Please enter a password." ascii //weight: 1
        $x_1_2 = "Public IP Address:" ascii //weight: 1
        $x_1_3 = "Upload failed with error:" ascii //weight: 1
        $x_1_4 = "Failed to upload file. Response:" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


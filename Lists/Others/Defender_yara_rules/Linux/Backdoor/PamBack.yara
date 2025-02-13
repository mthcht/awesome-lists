rule Backdoor_Linux_PamBack_A_2147813236_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Linux/PamBack.A!dha"
        threat_id = "2147813236"
        type = "Backdoor"
        platform = "Linux: Linux platform"
        family = "PamBack"
        severity = "Critical"
        info = "dha: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "7"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "error ServiceUnknown->%s" ascii //weight: 1
        $x_1_2 = "unix_setcred_return" ascii //weight: 1
        $x_3_3 = {0f b7 ff 48 8d 05 ?? ?? ?? ?? 48 c1 e7 ?? 48 01 c7 0f b7 57 ?? 66 85 d2 ?? ?? 31 c0 ?? ?? ?? ?? 4c 8b 47 08 0f b7 c8 89 c2 32 17 83 c0 01 41 32 14 08 88 14 0e 0f b7 57 02 66 39 c2}  //weight: 3, accuracy: Low
        $x_3_4 = {31 d2 4c 89 e7 e8 ?? ?? ?? ?? 85 c0 89 c3 ?? ?? 48 8b 4d ?? 48 85 c9 ?? ?? 0f b6 01 3c 2d ?? ?? 3c 2b ?? ?? 48 89 ca 44 89 f6 4c 89 e7}  //weight: 3, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_3_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}


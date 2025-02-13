rule Ransom_Linux_AvosLocker_A_2147810965_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Linux/AvosLocker.A!MTB"
        threat_id = "2147810965"
        type = "Ransom"
        platform = "Linux: Linux platform"
        family = "AvosLocker"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "7"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {3d 3d 22 57 6f 72 6c 64 49 44 2c 44 69 73 70 6c 61 79 4e 61 6d 65 22 20 76 6d 20 70 72 6f 63 65 73 73 20 6c 69 73 74 20 7c 20 74 61 69 6c 20 2d 6e 20 2b 32 20 7c 20 61 77 6b 20 2d 46 20 [0-8] 73 79 73 74 65 6d [0-4] 65 73 78 63 6c 69 20 76 6d 20 70 72 6f 63 65 73 73 20 6b 69 6c 6c 20 2d 2d 74 79 70 65 3d 66 6f 72 63 65 20 2d 2d 77 6f 72 6c 64 2d 69 64}  //weight: 5, accuracy: Low
        $x_1_2 = {41 76 6f 73 4c 69 6e 75 78 [0-3] 42 72 61 6e 63 68 20 4e 61 75 67 68 74 79 45 4c 46}  //weight: 1, accuracy: Low
        $x_1_3 = {41 74 74 65 6e 74 69 6f 6e [0-6] 59 6f 75 72 20 66 69 6c 65 73 20 68 61 76 65 20 62 65 65 6e 20 65 6e 63 72 79 70 74 65 64}  //weight: 1, accuracy: Low
        $x_1_4 = "ESXi VMs will be forced to shutdown when ran against ESXi paths" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_5_*) and 2 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Ransom_Linux_AvosLocker_B_2147853065_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Linux/AvosLocker.B!MTB"
        threat_id = "2147853065"
        type = "Ransom"
        platform = "Linux: Linux platform"
        family = "AvosLocker"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = ".avoslinux$" ascii //weight: 1
        $x_1_2 = "/README_FOR_RESTORE" ascii //weight: 1
        $x_1_3 = {74 74 70 3a 2f 2f 61 76 6f 73 [0-88] 2e 6f 6e 69 6f 6e}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


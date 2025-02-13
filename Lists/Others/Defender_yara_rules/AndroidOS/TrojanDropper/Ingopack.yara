rule TrojanDropper_AndroidOS_Ingopack_D_2147814182_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:AndroidOS/Ingopack.D!MTB"
        threat_id = "2147814182"
        type = "TrojanDropper"
        platform = "AndroidOS: Android operating system"
        family = "Ingopack"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "13"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = "com/magmamobile/app/la/conjugaison" ascii //weight: 10
        $x_10_2 = {63 6f 6d 2f 74 6f 75 74 61 70 70 72 65 6e 64 72 65 2f [0-16] 41 70 70 6c 69 63 61 74 69 6f 6e}  //weight: 10, accuracy: Low
        $x_1_3 = "/bootloader.dex" ascii //weight: 1
        $x_1_4 = "/.packer" ascii //weight: 1
        $x_1_5 = "BOOTSTRAPPER" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_10_*) and 3 of ($x_1_*))) or
            ((2 of ($x_10_*))) or
            (all of ($x*))
        )
}

rule TrojanDropper_AndroidOS_Ingopack_E_2147816036_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:AndroidOS/Ingopack.E!MTB"
        threat_id = "2147816036"
        type = "TrojanDropper"
        platform = "AndroidOS: Android operating system"
        family = "Ingopack"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "/oclassloader.dex" ascii //weight: 1
        $x_1_2 = ".packer" ascii //weight: 1
        $x_1_3 = "libdexload" ascii //weight: 1
        $x_1_4 = {61 74 74 61 63 68 42 61 73 65 43 6f 6e 74 65 78 74 74 00}  //weight: 1, accuracy: High
        $x_1_5 = {43 48 45 43 4b 50 4f 49 4e 54 20 33 00 64 61 6c 76 69 6b 2f 73 79 73 74 65 6d 2f 44 65 78 43 6c 61 73 73 4c 6f 61 64 65 72 00}  //weight: 1, accuracy: High
        $x_1_6 = "imaging/png/PngMetadataReader" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


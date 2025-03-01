rule Ransom_MacOS_FileCoder_A_2147745309_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:MacOS/FileCoder.A!MTB"
        threat_id = "2147745309"
        type = "Ransom"
        platform = "MacOS: "
        family = "FileCoder"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACHOHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "dv1208.local/key.php" ascii //weight: 2
        $x_2_2 = "/Documents/Skolan/DV1208/Projekt/EncryptFiles GUI/EncryptFilesGUI/Payment.o" ascii //weight: 2
        $x_1_3 = "/EncryptFilesGUI/ui_Decryption.h" ascii //weight: 1
        $x_1_4 = ":/images/decrypting.gif" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 2 of ($x_1_*))) or
            ((2 of ($x_2_*))) or
            (all of ($x*))
        )
}


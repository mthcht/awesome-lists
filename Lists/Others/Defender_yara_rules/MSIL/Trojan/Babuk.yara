rule Trojan_MSIL_Babuk_NB_2147952368_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Babuk.NB!MTB"
        threat_id = "2147952368"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Babuk"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {04 08 06 07 9a 7d ?? 00 00 04 00 08 7b ?? 00 00 04 6f}  //weight: 2, accuracy: Low
        $x_1_2 = "the decryption process will automatically begin" ascii //weight: 1
        $x_1_3 = "YOUR FILES HAVE BEEN ENCRYPTED" ascii //weight: 1
        $x_1_4 = "You have 1 hours to complete the payment before your files are permanently destroyed" ascii //weight: 1
        $x_1_5 = "Attempted to decrypt files with entered password" wide //weight: 1
        $x_1_6 = "Send the exact amount to the following Bitcoin address" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


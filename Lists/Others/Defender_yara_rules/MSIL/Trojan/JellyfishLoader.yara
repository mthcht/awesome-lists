rule Trojan_MSIL_JellyfishLoader_AJL_2147917658_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/JellyfishLoader.AJL!MTB"
        threat_id = "2147917658"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "JellyfishLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {2c 02 17 2a 00 03 73 ?? 00 00 0a 28 ?? 00 00 06 2c 0a 17 80 ?? 00 00 04 17 0a de 09 16 0a de 05 26 16 0a}  //weight: 2, accuracy: Low
        $x_1_2 = "269d53a8-8532-49ff-a310-44865b3b0db8" ascii //weight: 1
        $x_1_3 = "jellyfish\\JellyfishLoader\\obj\\x64\\Release\\qemu-ga.pdb" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


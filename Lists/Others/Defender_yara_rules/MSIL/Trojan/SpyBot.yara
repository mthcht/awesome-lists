rule Trojan_MSIL_SpyBot_AMTB_2147965562_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/SpyBot!AMTB"
        threat_id = "2147965562"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "SpyBot"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = "BegginerRAT.pdb" ascii //weight: 2
        $x_2_2 = {42 65 67 67 69 6e 65 72 52 41 54 2e [0-15] 2e 52 65 73 6f 75 72 63 65 73}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


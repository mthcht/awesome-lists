rule Backdoor_MSIL_CryptoDropper_2147742419_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:MSIL/CryptoDropper!MTB"
        threat_id = "2147742419"
        type = "Backdoor"
        platform = "MSIL: .NET intermediate language scripts"
        family = "CryptoDropper"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {fe 0e 00 00 00 11 00 59 7e ?? ?? ?? 04 61 d1 2a 50 00 fe 0e 01 00 fe 0c 00 00 fe 0c 01 00 58 [0-37] 20 20 05 00 00 [0-16] fe 0e 00 00 00 38 [0-32] fe 0e 00 00 00 11 00 59}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


rule Ransom_MSIL_SolidBit_N_2147828494_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:MSIL/SolidBit.N!MTB"
        threat_id = "2147828494"
        type = "Ransom"
        platform = "MSIL: .NET intermediate language scripts"
        family = "SolidBit"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {04 02 07 6f ?? ?? ?? 0a 7e ?? ?? ?? 04 07 7e ?? ?? ?? 04 8e 69 5d 91 61 28 ?? ?? ?? 06 28 ?? ?? ?? 06 26 07 17 58 0b 07 02 6f ?? ?? ?? 0a}  //weight: 1, accuracy: Low
        $x_1_2 = "$0ffa93b9-6bcb-4446-b298-f61986b78462" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


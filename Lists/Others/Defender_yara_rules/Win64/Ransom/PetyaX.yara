rule Ransom_Win64_PetyaX_AMTB_2147961642_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win64/PetyaX!AMTB"
        threat_id = "2147961642"
        type = "Ransom"
        platform = "Win64: Windows 64-bit platform"
        family = "PetyaX"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "PetyaXWPF.DecryptWindow" ascii //weight: 1
        $x_1_2 = "PetyaX.dll" ascii //weight: 1
        $x_1_3 = "Contact us for decryption key" ascii //weight: 1
        $x_1_4 = "Encrypted Files (*.petyax)|*.petyax" ascii //weight: 1
        $x_1_5 = "PetyaX.pdb" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


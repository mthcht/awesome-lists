rule Ransom_MSIL_Pillow_AMTB_2147963501_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:MSIL/Pillow!AMTB"
        threat_id = "2147963501"
        type = "Ransom"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Pillow"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "I am ThePillow Ransomware, created by UdoFreak." ascii //weight: 2
        $x_2_2 = ".PILLOW" ascii //weight: 2
        $x_1_3 = "[!!!] EXTREME WARNING: THIS PROGRAM ENCRYPTS THE ENTIRE DISK [!!!]" ascii //weight: 1
        $x_1_4 = " The console window will be HIDDEN during the process." ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_2_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}


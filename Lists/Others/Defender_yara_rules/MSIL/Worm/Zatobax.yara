rule Worm_MSIL_Zatobax_A_2147687753_0
{
    meta:
        author = "defender2yara"
        detection_name = "Worm:MSIL/Zatobax.A"
        threat_id = "2147687753"
        type = "Worm"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Zatobax"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {07 91 05 61 9c 07 17 58 0b 07 03 04 58 fe 04}  //weight: 1, accuracy: High
        $x_1_2 = "tazbox.zapto.org/downloader/miner/hh.exe" ascii //weight: 1
        $x_1_3 = "Microsoft\\hh.exehttp" ascii //weight: 1
        $x_1_4 = {28 3e 00 00 0a 0a 06 0d 16 0c 2b 0e 09 08 9a 0b 07 28 23 00 00 06 08 17 d6 0c 08 09 8e b7 32 ec}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


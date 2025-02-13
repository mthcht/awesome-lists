rule Worm_Win32_Mernzic_A_2147629009_0
{
    meta:
        author = "defender2yara"
        detection_name = "Worm:Win32/Mernzic.A"
        threat_id = "2147629009"
        type = "Worm"
        platform = "Win32: Windows 32-bit platform"
        family = "Mernzic"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "jej.jdjmjc" ascii //weight: 1
        $x_1_2 = "exitremoteevent" ascii //weight: 1
        $x_1_3 = "\\\\.\\pipe\\localcation" ascii //weight: 1
        $x_2_4 = {63 7a 6d 69 6e 69 6e 65 72 72 00 00 63 7a 6d 69 6e 69 6e 69 6e 00 00 00 5c 5c 2e 5c 70 69 70 65 5c 25 73 25 73 25 64 00 63 7a 6d 69 6e 69 6e 6f 75 74}  //weight: 2, accuracy: High
        $x_1_5 = "Don't use this computer!,ComputerName() Get failed :)" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((4 of ($x_1_*))) or
            ((1 of ($x_2_*) and 2 of ($x_1_*))) or
            (all of ($x*))
        )
}


rule Backdoor_MSIL_Capcren_A_2147712058_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:MSIL/Capcren.A!bit"
        threat_id = "2147712058"
        type = "Backdoor"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Capcren"
        severity = "Critical"
        info = "bit: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "You're under ATTACK!!" wide //weight: 1
        $x_1_2 = {63 00 61 00 70 00 73 00 63 00 72 00 65 00 65 00 6e 00 ?? ?? 43 00 3a 00 5c 00 [0-8] 2e 00 6a 00 70 00 67 00}  //weight: 1, accuracy: Low
        $x_1_3 = {73 00 76 00 63 00 68 00 6f 00 73 00 74 00 2e 00 65 00 78 00 65 00 ?? ?? 53 00 6f 00 66 00 74 00 77 00 61 00 72 00 65 00 5c 00 4d 00 69 00 63 00 72 00 6f 00 73 00 6f 00 66 00 74 00 5c 00 57 00 69 00 6e 00 64 00 6f 00 77 00 73 00 5c 00 43 00 75 00 72 00 72 00 65 00 6e 00 74 00 56 00 65 00 72 00 73 00 69 00 6f 00 6e 00 5c 00 52 00 75 00 6e 00}  //weight: 1, accuracy: Low
        $x_1_4 = {73 00 74 00 61 00 72 00 74 00 63 00 68 00 61 00 74 00 ?? ?? 63 00 61 00 70 00 ?? ?? 63 00 6c 00 6f 00 73 00 65 00 ?? ?? 6f 00 70 00 65 00 6e 00 63 00 64 00 ?? ?? 63 00 6c 00 6f 00 73 00 65 00 63 00 64 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}


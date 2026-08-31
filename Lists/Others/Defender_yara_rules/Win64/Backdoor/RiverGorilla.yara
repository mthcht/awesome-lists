rule Backdoor_Win64_RiverGorilla_L_2147977240_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win64/RiverGorilla.L!dha"
        threat_id = "2147977240"
        type = "Backdoor"
        platform = "Win64: Windows 64-bit platform"
        family = "RiverGorilla"
        severity = "Critical"
        info = "dha: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {45 4d 4d 21 6d 6e 60 65 64 65 21 60 6f 65 21 69 68 65 65 64 6f 21 67 74 ?? 62 75 68 6e 6f 21 64 79 64 62 74 75 64 65 21 72 74 62 62 64 72 72 67 74 6d 6d 78}  //weight: 1, accuracy: Low
        $x_1_2 = "bsd`ud^rbidetmde^u`rj" ascii //weight: 1
        $x_1_3 = "Dwdou!HE!01107!)Rxrudl!Mnf(" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


rule DoS_Win64_AshWiper_AA_2147947040_0
{
    meta:
        author = "defender2yara"
        detection_name = "DoS:Win64/AshWiper.AA!dha"
        threat_id = "2147947040"
        type = "DoS"
        platform = "Win64: Windows 64-bit platform"
        family = "AshWiper"
        severity = "Critical"
        info = "dha: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "list_disk" ascii //weight: 1
        $x_1_2 = "destroy_file" ascii //weight: 1
        $x_1_3 = "listFiles" ascii //weight: 1
        $x_1_4 = "mersenne_twister_engine" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


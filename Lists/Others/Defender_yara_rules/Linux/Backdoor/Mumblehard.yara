rule Backdoor_Linux_Mumblehard_A_2147695384_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Linux/Mumblehard.gen!A"
        threat_id = "2147695384"
        type = "Backdoor"
        platform = "Linux: Linux platform"
        family = "Mumblehard"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {56 5f 39 d3 75 13 81 fa ?? ?? 00 00 75 02 31 d2 81 c2 ?? 00 00 00 31 db 43 ac 30 d8 aa 43 e2 e2}  //weight: 1, accuracy: Low
        $x_1_2 = {89 f7 39 d3 75 13 81 fa ?? ?? 00 00 75 02 31 d2 81 c2 ?? 00 00 00 31 db 43 ac 30 d8 aa 43 e2 e2}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}


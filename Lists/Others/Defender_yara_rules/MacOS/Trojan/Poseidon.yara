rule Trojan_MacOS_Poseidon_A_2147765283_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MacOS/Poseidon.A"
        threat_id = "2147765283"
        type = "Trojan"
        platform = "MacOS: "
        family = "Poseidon"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_MACHOHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {48 83 ec 28 48 89 6c 24 20 48 8d 6c 24 20 48 8b 44 24 30 48 89 04 24 48 8b 44 24 38 48 89 44 24 08 48 c7 44 24 10 01 00 00 00 e8 52 6a 00 00}  //weight: 1, accuracy: High
        $x_1_2 = "pw_shell" ascii //weight: 1
        $x_1_3 = "Shellcode" ascii //weight: 1
        $x_1_4 = "shell.Shell" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


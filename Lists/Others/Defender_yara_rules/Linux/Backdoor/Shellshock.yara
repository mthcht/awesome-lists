rule Backdoor_Linux_Shellshock_A_2147689306_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Linux/Shellshock.A"
        threat_id = "2147689306"
        type = "Backdoor"
        platform = "Linux: Linux platform"
        family = "Shellshock"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {4a 55 4e 4b 20 46 6c 6f 6f 64 69 6e 67 20 25 73 3a 25 64 20 66 6f 72 20 25 64 20 73 65 63 6f 6e 64 73 2e 00}  //weight: 1, accuracy: High
        $x_1_2 = "/bin/busybox;echo -e '\\147\\141\\171\\146\\147\\164'" ascii //weight: 1
        $x_1_3 = {67 61 79 66 67 74 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (2 of ($x*))
}


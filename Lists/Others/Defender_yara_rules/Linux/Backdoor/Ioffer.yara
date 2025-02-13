rule Backdoor_Linux_Ioffer_A_2147826656_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Linux/Ioffer.A!xp"
        threat_id = "2147826656"
        type = "Backdoor"
        platform = "Linux: Linux platform"
        family = "Ioffer"
        severity = "Critical"
        info = "xp: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Cancels Transfer with ID = n" ascii //weight: 1
        $x_1_2 = "src/iroffer_upload.c" ascii //weight: 1
        $x_1_3 = "l_establishcon" ascii //weight: 1
        $x_1_4 = "lastcontact=%ld connecttime=%ld" ascii //weight: 1
        $x_1_5 = "Flood Protection Deactivated" ascii //weight: 1
        $x_1_6 = "adminpass JhGc7Ls2AOQSg" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


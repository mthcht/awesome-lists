rule HackTool_Linux_Koske_A_2147952725_0
{
    meta:
        author = "defender2yara"
        detection_name = "HackTool:Linux/Koske.A"
        threat_id = "2147952725"
        type = "HackTool"
        platform = "Linux: Linux platform"
        family = "Koske"
        severity = "High"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "hideproc.so" ascii //weight: 1
        $x_1_2 = "koske" ascii //weight: 1
        $x_1_3 = "/dev/shm/.hiddenpid" ascii //weight: 1
        $x_1_4 = "/proc/self/fd/%d" ascii //weight: 1
        $x_1_5 = "dlsym" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


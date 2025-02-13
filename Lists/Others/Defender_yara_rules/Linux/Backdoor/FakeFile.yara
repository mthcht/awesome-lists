rule Backdoor_Linux_FakeFile_A_2147818399_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Linux/FakeFile.A!xp"
        threat_id = "2147818399"
        type = "Backdoor"
        platform = "Linux: Linux platform"
        family = "FakeFile"
        severity = "Critical"
        info = "xp: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "pthread_cancel" ascii //weight: 1
        $x_1_2 = "file \"%s\"" ascii //weight: 1
        $x_1_3 = "chmod 777" ascii //weight: 1
        $x_1_4 = "gethostbyname" ascii //weight: 1
        $x_1_5 = "%s.bak" ascii //weight: 1
        $x_1_6 = "tar zxf \"%s\" -C \"%s\"" ascii //weight: 1
        $x_1_7 = "/.bash_profile" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


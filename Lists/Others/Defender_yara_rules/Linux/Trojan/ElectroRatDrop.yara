rule Trojan_Linux_ElectroRatDrop_A_2147772597_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Linux/ElectroRatDrop.A!!ElectroRatDrop.A"
        threat_id = "2147772597"
        type = "Trojan"
        platform = "Linux: Linux platform"
        family = "ElectroRatDrop"
        severity = "Critical"
        info = "ElectroRatDrop: an internal category used to refer to some threats"
        info = "A: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_ARHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "registerUser.go" ascii //weight: 1
        $x_1_2 = "osinfo.go" ascii //weight: 1
        $x_1_3 = "machineid.go" ascii //weight: 1
        $x_1_4 = "downloadFile.go" ascii //weight: 1
        $x_1_5 = "bin_linux.go" ascii //weight: 1
        $x_1_6 = "processKill.go" ascii //weight: 1
        $x_1_7 = "screenshot.go" ascii //weight: 1
        $x_1_8 = "uploadFolder.go" ascii //weight: 1
        $x_1_9 = "mdworker.go" ascii //weight: 1
        $x_1_10 = "hidefile.go" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

rule Trojan_Linux_ElectroRatDrop_B_2147778124_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Linux/ElectroRatDrop.B"
        threat_id = "2147778124"
        type = "Trojan"
        platform = "Linux: Linux platform"
        family = "ElectroRatDrop"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "13"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "registerUser.go" ascii //weight: 1
        $x_1_2 = "osinfo.go" ascii //weight: 1
        $x_1_3 = "machineid.go" ascii //weight: 1
        $x_1_4 = "downloadFile.go" ascii //weight: 1
        $x_1_5 = "bin_linux.go" ascii //weight: 1
        $x_1_6 = "processKill.go" ascii //weight: 1
        $x_1_7 = "screenshot.go" ascii //weight: 1
        $x_1_8 = "uploadFolder.go" ascii //weight: 1
        $x_10_9 = "mdworker.go" ascii //weight: 10
        $x_1_10 = "hidefile.go" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_10_*) and 3 of ($x_1_*))) or
            (all of ($x*))
        )
}


rule Ransom_Linux_RedAlert_A_2147825993_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Linux/RedAlert.A"
        threat_id = "2147825993"
        type = "Ransom"
        platform = "Linux: Linux platform"
        family = "RedAlert"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Run command for stop all running VM" ascii //weight: 1
        $x_1_2 = "File for encrypt" ascii //weight: 1
        $x_1_3 = ".vmdk" ascii //weight: 1
        $x_1_4 = "[ N13V ]" ascii //weight: 1
        $x_1_5 = "hwnrtxp:f:" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_Linux_RedAlert_B_2147846373_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Linux/RedAlert.B!MTB"
        threat_id = "2147846373"
        type = "Ransom"
        platform = "Linux: Linux platform"
        family = "RedAlert"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "[ N13V " ascii //weight: 1
        $x_1_2 = "/home/a13x/Documents/PJ/main2nix/CLionProjects/ntru_code" ascii //weight: 1
        $x_1_3 = "enc.file" ascii //weight: 1
        $x_1_4 = ".vmdk" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


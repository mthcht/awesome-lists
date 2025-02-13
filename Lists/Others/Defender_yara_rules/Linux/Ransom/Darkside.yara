rule Ransom_Linux_Darkside_DA_2147913737_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Linux/Darkside.DA"
        threat_id = "2147913737"
        type = "Ransom"
        platform = "Linux: Linux platform"
        family = "Darkside"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "Removing Self Executable..." ascii //weight: 2
        $x_2_2 = "Total Encrypted Files.........." ascii //weight: 2
        $x_1_3 = "Ignored  VM[" ascii //weight: 1
        $x_1_4 = "kill-process.enable" ascii //weight: 1
        $x_1_5 = "kill-vm.enable" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 3 of ($x_1_*))) or
            ((2 of ($x_2_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}


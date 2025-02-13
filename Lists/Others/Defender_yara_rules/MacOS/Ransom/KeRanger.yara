rule Ransom_MacOS_KeRanger_2147741124_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:MacOS/KeRanger"
        threat_id = "2147741124"
        type = "Ransom"
        platform = "MacOS: "
        family = "KeRanger"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_MACHOHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "/Resources/General.rtf" ascii //weight: 2
        $x_1_2 = "/Library/kernel_service" ascii //weight: 1
        $x_1_3 = "/Library/.kernel_pid" ascii //weight: 1
        $x_1_4 = "/Library/.kernel_time" ascii //weight: 1
        $x_1_5 = "/Library/.kernel_complete" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_MacOS_KeRanger_A_2147751014_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:MacOS/KeRanger.A!MTB"
        threat_id = "2147751014"
        type = "Ransom"
        platform = "MacOS: "
        family = "KeRanger"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACHOHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "%s/Library/.kernel_complete" ascii //weight: 1
        $x_1_2 = "README_FOR_DECRYPT.txt" ascii //weight: 1
        $x_1_3 = ".onion.nu" ascii //weight: 1
        $x_1_4 = ".onion.link" ascii //weight: 1
        $x_1_5 = ".encrypted" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (4 of ($x*))
}


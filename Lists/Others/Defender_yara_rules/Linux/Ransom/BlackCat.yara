rule Ransom_Linux_BlackCat_A_2147808375_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Linux/BlackCat.A!MTB"
        threat_id = "2147808375"
        type = "Ransom"
        platform = "Linux: Linux platform"
        family = "BlackCat"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "esxcli --formatter=csv --format-param=fields==" ascii //weight: 1
        $x_1_2 = "esxcli vm process kill --type=force --world-id=" ascii //weight: 1
        $x_1_3 = "vm process list | awk -F " ascii //weight: 1
        $x_1_4 = "enable_esxi_vm_kill" ascii //weight: 1
        $x_1_5 = "enable_esxi_vm_snapshot_kill" ascii //weight: 1
        $x_1_6 = "default_file_cipher" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_Linux_BlackCat_B_2147823190_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Linux/BlackCat.B!MTB"
        threat_id = "2147823190"
        type = "Ransom"
        platform = "Linux: Linux platform"
        family = "BlackCat"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "esxcli --formatter=csv --format-param=fields==" ascii //weight: 1
        $x_1_2 = "esxcli vm process kill --type=force --world-id=" ascii //weight: 1
        $x_1_3 = "locker::core::os::linux::command" ascii //weight: 1
        $x_1_4 = "locker::core::os::linux::esxi" ascii //weight: 1
        $x_1_5 = "locker::core::pipeline::file_worker_pool" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_Linux_BlackCat_C_2147846608_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Linux/BlackCat.C!MTB"
        threat_id = "2147846608"
        type = "Ransom"
        platform = "Linux: Linux platform"
        family = "BlackCat"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "renameprelocknote" ascii //weight: 1
        $x_1_2 = "kill-vm-includekill-vm-exclude" ascii //weight: 1
        $x_1_3 = "esxcli vm process kill" ascii //weight: 1
        $x_1_4 = "esxcli --formatter=csv --format-param=fields==" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_Linux_BlackCat_H_2147916313_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Linux/BlackCat.H!MTB"
        threat_id = "2147916313"
        type = "Ransom"
        platform = "Linux: Linux platform"
        family = "BlackCat"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {55 48 83 3d 2f 45 3c 00 00 48 89 e5 74 1a 48 8b 05 cb 3f 3d 00 48 85 c0 74 0e 48 8d 3d 17 45 3c 00 49 89 c3 c9 41 ff e3}  //weight: 1, accuracy: High
        $x_1_2 = {41 57 41 56 41 54 53 50 48 8b 4f 08 48 89 c8 48 29 f0 48 39 d0 0f 83 e3 00 00 00 48 01 d6 0f 82 e6 00 00 00 49 89 ff 48 8d 04 09 48 39 f0 48 0f 47 f0}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


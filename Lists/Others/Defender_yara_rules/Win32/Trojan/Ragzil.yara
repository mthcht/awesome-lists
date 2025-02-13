rule Trojan_Win32_Ragzil_B_2147851616_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Ragzil.B"
        threat_id = "2147851616"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Ragzil"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = ".vmt.exe" ascii //weight: 1
        $x_1_2 = "/enc.exe" ascii //weight: 1
        $x_1_3 = "anti_vm_exclusion_name" ascii //weight: 1
        $x_1_4 = "add_folder_to_exclusions" ascii //weight: 1
        $x_1_5 = "start_in_memory_path" ascii //weight: 1
        $x_1_6 = "pump_file" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (4 of ($x*))
}

rule Trojan_Win32_Ragzil_C_2147851649_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Ragzil.C"
        threat_id = "2147851649"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Ragzil"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_3_1 = "\\antivm.rs" ascii //weight: 3
        $x_3_2 = "\\runpe.rs" ascii //weight: 3
        $x_1_3 = "\\config.rs" ascii //weight: 1
        $x_1_4 = "\\crypto.rs" ascii //weight: 1
        $x_1_5 = "\\utils.rs" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_3_*) and 1 of ($x_1_*))) or
            ((2 of ($x_3_*))) or
            (all of ($x*))
        )
}


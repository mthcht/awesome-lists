rule Trojan_Linux_ShortLeash_A_2147974190_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Linux/ShortLeash.A!AMTB"
        threat_id = "2147974190"
        type = "Trojan"
        platform = "Linux: Linux platform"
        family = "ShortLeash"
        severity = "Critical"
        info = "AMTB: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "9"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "/proc/self/exe" ascii //weight: 1
        $x_1_2 = "%s.%d_%d" ascii //weight: 1
        $x_1_3 = "/bin/sh" ascii //weight: 1
        $x_1_4 = "npxXoudifFeEgGaACScs" ascii //weight: 1
        $x_1_5 = "hlLjztqZ" ascii //weight: 1
        $x_1_6 = "/proc/stat" ascii //weight: 1
        $x_1_7 = "/proc/cpuinfo" ascii //weight: 1
        $x_1_8 = "/sys/devices/system/cpu" ascii //weight: 1
        $x_1_9 = "/bin:/usr/bin" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Linux_ShortLeash_AMTB_2147974194_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Linux/ShortLeash!AMTB"
        threat_id = "2147974194"
        type = "Trojan"
        platform = "Linux: Linux platform"
        family = "ShortLeash"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "socket.async_send" ascii //weight: 1
        $x_1_2 = "St23_Sp_counted_ptr_inplaceIN2ff6runnerESaIS1_ELN9__gnu_cxx12_Lock_policyE2EE" ascii //weight: 1
        $x_1_3 = "St23_Sp_counted_ptr_inplaceIN2ff7network7x509crtESaIS2_ELN9__gnu_cxx12_Lock_policyE2EE" ascii //weight: 1
        $x_1_4 = "XL|St23_Sp_counted_ptr_inplaceIN2ff7network4pkeyESaIS2_ELN9__gnu_cxx12_Lock_policyE2EE" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


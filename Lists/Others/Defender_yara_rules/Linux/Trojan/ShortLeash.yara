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

rule Trojan_Linux_ShortLeash_DA_2147975157_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Linux/ShortLeash.DA!MTB"
        threat_id = "2147975157"
        type = "Trojan"
        platform = "Linux: Linux platform"
        family = "ShortLeash"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {78 fd bd 27 c2 17 07 00 6c 02 b3 af 84 02 bf af 80 02 be af 7c 02 b7 af 78 02 b6 af 74 02 b5 af 70 02 b4 af 68 02 b2 af 64 02 b1 af 60 02 b0 af 25 98 80 00 34 02 a0 af 2a 00 e1 04 4c 02 a2 af 00 80 02 3c 26 38 e2 00 41 00 02 3c c4 61 42 24 58 02 a2 af ff 7f}  //weight: 1, accuracy: High
        $x_1_2 = {02 18 a0 45 00 00 02 82 18 2b 14 60 ff fd 24 42 ff ff 00 94 10 2b 00 82 a0 0b 02 f4 b8 23 10 c0 00 30 8f a2 02 9c 8f a2 02 9c 27 de 00 04 00 57 10 23 af a2 02 9c 03 d2 10 2b 10 40 00 31 8f a2 02 9c 04 40 00 2f 27 b7 02 19 8f}  //weight: 1, accuracy: High
        $x_1_3 = {9f e7 03 10 82 e7 f7 ff ff ea d0 00 c5 e1 13 20 42 e2 d8 80 c5 e1 b0 c1 c4 e1 f0 00 c4 e1 13 00 84 e2 12 10 d5 e5 f8 80 c4 e1 2c 30 0b e5 12 10 c4 e5 13 10 85 e2 38 e3 ff eb b0 21 d5 e1 2c 30}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}


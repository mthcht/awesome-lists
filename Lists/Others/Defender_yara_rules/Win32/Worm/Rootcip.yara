rule Worm_Win32_Rootcip_E_2147598524_0
{
    meta:
        author = "defender2yara"
        detection_name = "Worm:Win32/Rootcip.E"
        threat_id = "2147598524"
        type = "Worm"
        platform = "Win32: Windows 32-bit platform"
        family = "Rootcip"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_3_1 = {2e 64 6c 6c 00 43 61 6c 6c 57 6e 64 50 72 6f 63 00 47 65 74 4d 73 67 44 61 74 61 00 47 65 74 4d}  //weight: 3, accuracy: High
        $x_3_2 = {4d 6f 75 73 65 50 72 6f 63 00 53 74 61 72 74 48 6f 6f 6b 00 53 74 6f 70 48 6f 6f 6b 00}  //weight: 3, accuracy: High
        $x_2_3 = {5b 45 6e 74 65 72 5d 00 5b 42 61 63 6b 53 70 61 63 65 5d}  //weight: 2, accuracy: High
        $x_1_4 = "%04d-%02d-%02d %02d:%02d" ascii //weight: 1
        $x_1_5 = "[TiTle=NULL]" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_3_*) and 2 of ($x_1_*))) or
            ((2 of ($x_3_*) and 1 of ($x_2_*))) or
            (all of ($x*))
        )
}

rule Worm_Win32_Rootcip_A_2147611310_0
{
    meta:
        author = "defender2yara"
        detection_name = "Worm:Win32/Rootcip.A"
        threat_id = "2147611310"
        type = "Worm"
        platform = "Win32: Windows 32-bit platform"
        family = "Rootcip"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "41"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "\\hack_da_ipd" ascii //weight: 10
        $x_10_2 = "\\SYSTEM32\\_tdiserv_\\svchost.exe" ascii //weight: 10
        $x_10_3 = "ZwQuerySystemInformation" ascii //weight: 10
        $x_10_4 = "KeServiceDescriptorTable" ascii //weight: 10
        $x_1_5 = "_tdiserv_HOOK" ascii //weight: 1
        $x_1_6 = "_tdipacket_HOOK" ascii //weight: 1
        $x_1_7 = "\\TdiUpdate.sys" ascii //weight: 1
        $x_1_8 = "TdiHook Update Driver" ascii //weight: 1
        $x_1_9 = "\\\\.\\TdiTransferClient" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((4 of ($x_10_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}


rule Trojan_UEFI_MosaicRegressor_A_2147765815_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:UEFI/MosaicRegressor.A"
        threat_id = "2147765815"
        type = "Trojan"
        platform = "UEFI: "
        family = "MosaicRegressor"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "28"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "NtfsPkg\\NtfsDxe\\ntfs\\bootsect.c" ascii //weight: 1
        $x_1_2 = "NtfsPkg\\NtfsDxe\\NtfsFlush.c" ascii //weight: 1
        $x_1_3 = "NtfsPkg\\NtfsDxe\\NtfsInfo.c" ascii //weight: 1
        $x_1_4 = "NtfsPkg\\NtfsDxe\\NtfsSetPosition.c" ascii //weight: 1
        $x_1_5 = "NtfsPkg\\NtfsDxe\\NtfsGetPosition.c" ascii //weight: 1
        $x_1_6 = "NtfsPkg\\NtfsDxe\\NtfsWrite.c" ascii //weight: 1
        $x_1_7 = "NtfsPkg\\NtfsDxe\\NtfsRead.c" ascii //weight: 1
        $x_1_8 = "NtfsPkg\\NtfsDxe\\NtfsDelete.c" ascii //weight: 1
        $x_1_9 = "NtfsPkg\\NtfsDxe\\NtfsClose.c" ascii //weight: 1
        $x_10_10 = "EFI_ERROR" ascii //weight: 10
        $x_10_11 = "device is dirty, will now sync\\n" ascii //weight: 10
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_10_*) and 8 of ($x_1_*))) or
            (all of ($x*))
        )
}


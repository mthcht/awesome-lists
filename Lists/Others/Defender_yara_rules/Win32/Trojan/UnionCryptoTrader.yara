rule Trojan_Win32_UnionCryptoTrader_2147750008_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/UnionCryptoTrader!ibt"
        threat_id = "2147750008"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "UnionCryptoTrader"
        severity = "Critical"
        info = "ibt: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "/tempdisk1folder\"C:\\TEMP\\{00000001-0001-0002-0000-000000000049D4D4}\"  /IS_temp" ascii //weight: 1
        $x_1_2 = "RoVFRoVFRoVFRoVFRoVFRoVFRoVFRoVFRoVFRoVFRoVFRoVFRoVFRoVFRoVFRo" ascii //weight: 1
        $x_3_3 = "UnionCryptoTraderSetup.exe" wide //weight: 3
        $x_3_4 = "UnionCrypto Corporation. All Rights Reserved" wide //weight: 3
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_3_*) and 2 of ($x_1_*))) or
            ((2 of ($x_3_*))) or
            (all of ($x*))
        )
}


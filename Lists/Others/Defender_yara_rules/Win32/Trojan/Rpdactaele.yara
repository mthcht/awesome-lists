rule Trojan_Win32_Rpdactaele_A_2147728914_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Rpdactaele.A"
        threat_id = "2147728914"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Rpdactaele"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "131"
        strings_accuracy = "High"
    strings:
        $x_100_1 = "c8ba73d2-3d55-429c-8e9a-c44f006f69fc" ascii //weight: 100
        $x_1_2 = {70 72 6e 6d 73 30 30 33 2e 69 6e 66 5f 61 6d 64 36 34 2a 00}  //weight: 1, accuracy: High
        $x_1_3 = "D:(A;;FA;;;BA)(A;OICIIO;GA;;;BA)(A;;FA;;;SY)(A;OICIIO;GA" ascii //weight: 1
        $x_1_4 = "D:(A;;FA;;;WD)" ascii //weight: 1
        $x_10_5 = "ncalrpc" ascii //weight: 10
        $x_10_6 = "ZwSetInformationFile" ascii //weight: 10
        $x_10_7 = "RpcBindingSetAuthInfoExW" ascii //weight: 10
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_100_*) and 3 of ($x_10_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_Rpdactaele_C_2147728916_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Rpdactaele.C"
        threat_id = "2147728916"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Rpdactaele"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1130"
        strings_accuracy = "High"
    strings:
        $x_1000_1 = "\\..\\..\\..\\..\\..\\" ascii //weight: 1000
        $x_100_2 = {34 63 39 64 62 66 31 39 2d 64 33 39 65 2d 34 62 62 39 2d 39 30 65 65 2d 38 66 37 31 37 39 62 32 30 32 38 33 00}  //weight: 100, accuracy: High
        $x_10_3 = "ncalrpc" ascii //weight: 10
        $x_10_4 = "RpcBindingSetAuthInfoExW" ascii //weight: 10
        $x_10_5 = "ZwSetInformationFile" ascii //weight: 10
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


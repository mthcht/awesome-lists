rule Trojan_Win64_SpyBoy_SA_2147849894_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/SpyBoy.SA!MTB"
        threat_id = "2147849894"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "SpyBoy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Terminator.sys" ascii //weight: 1
        $x_1_2 = "Terminating ALL EDR/XDR/AVs" ascii //weight: 1
        $x_1_3 = "ZemanaAntiMalware" wide //weight: 1
        $x_1_4 = "C:\\Users\\anash\\source\\repos\\zan\\x64\\Debug\\zan.pdb" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_SpyBoy_EC_2147919989_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/SpyBoy.EC!MTB"
        threat_id = "2147919989"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "SpyBoy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "11"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "AntiMalware\\bin\\zam64.pdb" ascii //weight: 2
        $x_2_2 = "\\DosDevices\\ZemanaAntiMalware" ascii //weight: 2
        $x_2_3 = "DriverEntry():ZAM Driver - v286 Loaded" ascii //weight: 2
        $x_1_4 = "ZmnClnDeleteFilesProcessor" ascii //weight: 1
        $x_1_5 = "ZmnClnCopyFilesProcessor" ascii //weight: 1
        $x_1_6 = "ZmnClnProcessEntries" ascii //weight: 1
        $x_1_7 = "ZmnClnRunCleaner" ascii //weight: 1
        $x_1_8 = "ZmnIoCreateFileBypassFilters" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


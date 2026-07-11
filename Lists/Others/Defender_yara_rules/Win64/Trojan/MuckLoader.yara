rule Trojan_Win64_MuckLoader_MU_2147973403_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/MuckLoader.MU!MTB"
        threat_id = "2147973403"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "MuckLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "\\Desktop\\UpdateFactory\\compiler\\" ascii //weight: 1
        $x_1_2 = "main.MpClientUtilExportFunctions" ascii //weight: 1
        $x_1_3 = "\\go\\src\\runtime\\cgo" ascii //weight: 1
        $x_1_4 = "_cgoexp_" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


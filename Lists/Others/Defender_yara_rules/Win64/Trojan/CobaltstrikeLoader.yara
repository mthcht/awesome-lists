rule Trojan_Win64_CobaltstrikeLoader_LKAM_2147888312_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/CobaltstrikeLoader.LKAM!MTB"
        threat_id = "2147888312"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "CobaltstrikeLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "1github.com/larksuite/oapi-sdk-go/v3/service/im/v1" ascii //weight: 1
        $x_1_2 = "github.com/latortuga71/GoPeLoader/pkg/peloader" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


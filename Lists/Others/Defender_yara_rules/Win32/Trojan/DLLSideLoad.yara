rule Trojan_Win32_DLLSideLoad_SO_2147969828_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/DLLSideLoad.SO!MTB"
        threat_id = "2147969828"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "DLLSideLoad"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "/cmd/backconnect_dll" ascii //weight: 1
        $x_2_2 = "://api1.mylabubus.shop/register" ascii //weight: 2
        $x_2_3 = "://api1.checkupdatesnow.xyz/register" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 1 of ($x_1_*))) or
            ((2 of ($x_2_*))) or
            (all of ($x*))
        )
}


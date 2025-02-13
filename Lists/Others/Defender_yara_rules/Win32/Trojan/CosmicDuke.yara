rule Trojan_Win32_CosmicDuke_CCIE_2147908906_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/CosmicDuke.CCIE!MTB"
        threat_id = "2147908906"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "CosmicDuke"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {53 68 28 21 40 00 bf f4 20 40 00 57 ff 75 fc ff 15}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


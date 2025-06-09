rule Trojan_Win64_ScarletFlash_NS_2147901480_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/ScarletFlash.NS!MTB"
        threat_id = "2147901480"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "ScarletFlash"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {83 3d 29 82 01 00 00 75 36 48 85 c9 75 1a e8 11 10 ff ff c7 00 ?? ?? ?? ?? e8 2e e7 fe ff b8 ?? ?? ?? ?? 48 83 c4 28}  //weight: 5, accuracy: Low
        $x_1_2 = "bloxcrusher.pdb" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


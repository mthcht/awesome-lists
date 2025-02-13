rule Trojan_Win32_Libie_GNF_2147893844_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Libie.GNF!MTB"
        threat_id = "2147893844"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Libie"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "aSUZHJXEH" ascii //weight: 1
        $x_1_2 = "_nLMqJJuMIqJBqKByVIpQBqQBeJ8dJ8eM9U" ascii //weight: 1
        $x_1_3 = "fVXiYZ_OP_OPfVWfST_POcWYTJLrin" ascii //weight: 1
        $x_1_4 = "mPArSDpRBqRAnRAoSAoT@rVAtWBuXCwZEw" ascii //weight: 1
        $x_1_5 = ".vmp0" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


rule Trojan_MSIL_DiskKill_RPX_2147892274_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/DiskKill.RPX!MTB"
        threat_id = "2147892274"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "DiskKill"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "virusthing" ascii //weight: 1
        $x_1_2 = "Hacking stuff" ascii //weight: 1
        $x_1_3 = "bingbong" wide //weight: 1
        $x_1_4 = "takeown.exe" wide //weight: 1
        $x_1_5 = "friendl.dll" wide //weight: 1
        $x_1_6 = "DisableTaskMgr" wide //weight: 1
        $x_1_7 = "bin\\marker.txt" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


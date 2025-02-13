rule Ransom_Win32_UdeRansom_SK_2147760733_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/UdeRansom.SK!MTB"
        threat_id = "2147760733"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "UdeRansom"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "16"
        strings_accuracy = "High"
    strings:
        $x_5_1 = "D:/GoProj/src/YourRansom/data.go" ascii //weight: 5
        $x_5_2 = "Hey guys, why not care?" ascii //weight: 5
        $x_5_3 = "edu edition of YourRansom" wide //weight: 5
        $x_1_4 = "Go build ID" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


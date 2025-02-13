rule TrojanDropper_Win32_MultiDropper_AO_2147632093_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:Win32/MultiDropper.AO"
        threat_id = "2147632093"
        type = "TrojanDropper"
        platform = "Win32: Windows 32-bit platform"
        family = "MultiDropper"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "\\Windows\\CurrentVersion\\Explorer\\Browser Helper Objects" wide //weight: 1
        $x_1_2 = "regsvr32 /s shdocwv.dll" wide //weight: 1
        $x_1_3 = "Brasil" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


rule Worm_Win32_FakeFolder_ARR_2147960057_0
{
    meta:
        author = "defender2yara"
        detection_name = "Worm:Win32/FakeFolder.ARR!MTB"
        threat_id = "2147960057"
        type = "Worm"
        platform = "Win32: Windows 32-bit platform"
        family = "FakeFolder"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "20"
        strings_accuracy = "High"
    strings:
        $x_15_1 = "em32\\flash.exe /f" wide //weight: 15
        $x_4_2 = "flash.exe" ascii //weight: 4
        $x_1_3 = "screen taked" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


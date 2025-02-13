rule SoftwareBundler_Win32_LinkPadBundle_366361_0
{
    meta:
        author = "defender2yara"
        detection_name = "SoftwareBundler:Win32/LinkPadBundle"
        threat_id = "366361"
        type = "SoftwareBundler"
        platform = "Win32: Windows 32-bit platform"
        family = "LinkPadBundle"
        severity = "High"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "Product information is missing. Do not change the filename." ascii //weight: 2
        $x_2_2 = {00 5c 6c 69 6e 6b 2e 74 78 74}  //weight: 2, accuracy: High
        $x_1_3 = "hreturntoinstaller hextras=id:" ascii //weight: 1
        $x_1_4 = "GenericSetup.exe" ascii //weight: 1
        $x_1_5 = "this://app/*" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 3 of ($x_1_*))) or
            ((2 of ($x_2_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

